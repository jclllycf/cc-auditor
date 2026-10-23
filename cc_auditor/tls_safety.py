"""Verified client context without honoring SSLKEYLOGFILE or writing handshake secrets."""
import ssl

def verified_context():
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context
