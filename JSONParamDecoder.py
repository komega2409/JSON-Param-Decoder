import json
from collections import OrderedDict

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IMessageEditorController
from burp import IParameter
from burp import IContextMenuFactory
from burp import IHttpListener

# Java imports
from javax.swing import JMenuItem
from java.util import List, ArrayList

# Global Variables
# Force extension
_forceJSON = False

# Repeater tool flag
TOOL_REPEATER = 64

# Content-Types for detection: application/x-www-form-urlencoded
supportedContentTypes = ["application/x-www-form-urlencoded"]
jsonContentType = "application/json"

# JSON Parameter's name
jsonParam = 'dataJson'

# Identify extension header to auto-concat jsonParam + value when "Send" in Repeater
extensionHeader = 'X-JSON-Param'

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName('JSON Param Decoder v1.0 beta')
        callbacks.registerMessageEditorTabFactory(self)
        callbacks.registerContextMenuFactory(self)
        #  Register listener to update body when header extensionHeader exists
        callbacks.registerHttpListener(self)

        return
    
    def processHttpMessage(self, toolFlag, isRequest, content):

        # handle request only!
        if not isRequest:
            return
        
        # process message in Repeater only!
        if toolFlag == TOOL_REPEATER:
            requestBytes = content.getRequest()
            request = self._helpers.analyzeRequest(content)
            headers = request.getHeaders()
            
            # check whether extensionHeader exists
            if extensionHeader in str(headers):
                # replace jsonContentType with supportedContentTypes => avoid wrong content-type when Send
                newHeaders = [header.replace(jsonContentType, supportedContentTypes[0]) for header in headers]
                decodeHelper = DecodeHelper()
                bodyOffset = request.getBodyOffset()
                bodyBytes = requestBytes[bodyOffset:]
                bodyString = bytearray(bodyBytes).decode('utf-8')
                jsonValue = json.dumps(json.loads(bodyString, object_pairs_hook=OrderedDict))
                requestBody = jsonParam + '=' + decodeHelper.urlEncodeAllChars(jsonValue)
                # build new http request
                newRequest = self._helpers.buildHttpMessage(newHeaders, self._helpers.stringToBytes(requestBody))
                # set new http request
                content.setRequest(newRequest)

    
    def createNewInstance(self, controller, editable):
        return JSONParamDecoder(self, controller, editable)
    
    def createMenuItems(self, IContextMenuInvocation):
        global _forceJSON
        menuItemList = ArrayList()
        menuItemList.add(JMenuItem(menuItems[_forceJSON], actionPerformed = self.onClick))

        return menuItemList

    def onClick(self, event):
        global _forceJSON
        _forceJSON = not _forceJSON

class JSONParamDecoder(IMessageEditorTab):
    def __init__(self, extender, controller, editable):
        self._extender = extender
        self._helpers = extender._helpers
        self._editable = editable

        self._txtInput = extender._callbacks.createMessageEditor(controller, editable)

        self._jsonMagicMark = ['{"', '["', '[{']

        return

    def getTabCaption(self):
        return "JSON Param Decoder"
        
    def getUiComponent(self):
        return self._txtInput.getComponent()

    def isEnabled(self, content, isRequest):
        global _forceJSON

        if isRequest:
            r = self._helpers.analyzeRequest(content)
        else:
            r = self._helpers.analyzeResponse(content)

        msg = content[r.getBodyOffset():].tostring()
        
        if _forceJSON and len(msg) > 2 and msg[:2] in self._jsonMagicMark:
            return True
        
        for header in r.getHeaders():
            if header.lower().startswith("content-type:"):
                content_type = header.split(":")[1].lower()

                for allowedType in supportedContentTypes:
                    if content_type.find(allowedType) > 0:
                        return True
        return False
    
    def setMessage(self, content, isRequest):
        if content is None:
            self._txtInput.setMessage(None)

        else:
            if isRequest:
                r = self._helpers.analyzeRequest(content)
            headers = r.getHeaders()
            updatedheaders = self.updateHeader(headers, 'Content-Type', jsonContentType)
            paramsInRequest = []
            for param in r.getParameters():
                paramsInRequest.append(param.getName())
            jsonParamIndex = paramsInRequest.index(jsonParam)
            jsonParamValue = r.getParameters()[jsonParamIndex].getValue()
            # Remove jsonParam's name and replace with data in json format
            jsonValue = self._helpers.urlDecode(jsonParamValue)
                
            # Get raw request instead of body only
            msg = content.tostring()

            # Find garbage index
            try:
                boundary = min(
                                jsonValue.index('{') if '{' in msg else len(msg),
                                jsonValue.index('[') if '[' in msg else len(msg)
                            )
            except ValueError:
                print('Sure this is JSON?')
                return
            
            garbage = jsonValue[:boundary]
            clean = jsonValue[boundary:]

            try:
                prettyMsg = garbage.strip() + '\n' + json.dumps(json.loads(clean), indent=4)

            except:
                prettyMsg = garbage + clean

            self._txtInput.setMessage(self._helpers.buildHttpMessage(updatedheaders, prettyMsg), True)

        self._currentMessage = content
        return


    def getMessage(self):
        decodeHelper = DecodeHelper()
        if self._txtInput.isMessageModified():
            try:
                preData = self._txtInput.getMessage().tostring()
                boundary = min(preData.index('{'), preData.index('['))
                garbage = preData[boundary:]
                clean = preData[boundary:]
                jsonValue = garbage + json.dumps(json.loads(clean, object_pairs_hook=OrderedDict))
            except:
                jsonValue = self._helpers.bytesToString(self._txtInput.getMessage())

                boundary = jsonValue.index('{')
                clean = jsonValue[boundary:]
                jsonValue = json.dumps(json.loads(clean, object_pairs_hook=OrderedDict))
                jsonParamValue = decodeHelper.urlEncodeAllChars(jsonValue)
                body = jsonParam + '=' + jsonParamValue

            # Reconstruct request/response
            r = self._helpers.analyzeRequest(self._currentMessage)
            headers = r.getHeaders()
            
            # only set content-type for x-www-form-urlencoded 
            if 'x-www-form-urlencoded' in headers:
                updatedheaders = self.updateHeader(headers, 'Content-Type', jsonContentType)
                return self._helpers.buildHttpMessage(updatedheaders, self._helpers.stringToBytes(body))
            else:
                return self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body))
        else:
            self._currentMessage

    def isModified(self):
        return self._txtInput.isMessageModified()
    
    def updateHeader(self, headers, headerName, value):
        updatedHeaders = []
        for header in headers:
            if headerName in header:
                # headers.remove(header)
                updatedHeaders.append(headerName + ':' + ' ' + value)
            else:
                updatedHeaders.append(header)
        # add custom header to identify JSON Param Decoder tab
        updatedHeaders.append(extensionHeader + ':' + ' ' + '1')
        return updatedHeaders
    
    def addHeader(self, headers, headerName, value):
        pass
    
class DecodeHelper():
    def urlEncodeAllChars(self, inputString):
        # foo is org.python.proxies.__main__ => don't know what is this? But this function got 2 arguments? 
        encodedString = ""
        for char in inputString:
            if char.isalnum() or char in ['-', '_', '.', '~']:
                encodedString += char
            else:
                encodedString += '%' + '{:02x}'.format(ord(char)).upper()
        return encodedString