import socket
import ssl
import datetime

def parse_x509_name(name_tuple):
    """Parse X509 name tuple into dict."""
    result = {}
    if not name_tuple:
        return result
    for rdn in name_tuple:
        for attr in rdn:
            result[attr[0]] = attr[1]
    return result

def run(context):
    """
    Connects to the target port via SSL/TLS and extracts cipher/version info.
    Also parses certificate details if available.
    """
    debug = context.get('debug', lambda x: None)
    debug("Starting TLS inspection...")
    target = context.get('target')
    port = context.get('port')
    timeout = 5

    if not target or not port:
        return None

    result = {}

    try:
        # Create SSL context (unverified, but we'll try to get cert)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=target) as ssock:
                version = ssock.version()
                cipher_info = ssock.cipher()
                
                result["ssl_version"] = version
                result["ssl_cipher"] = cipher_info[0] if cipher_info else "unknown"
                result["ssl_bits"] = cipher_info[2] if cipher_info and len(cipher_info) > 2 else 0
                result["service_tunnel"] = "ssl"
                
                # Try to get certificate
                # In CERT_NONE mode, getpeercert(binary_form=False) returns {}
                # We need to try a different approach or accept binary
                try:
                    # This gives decoded dict when verify_mode != CERT_NONE
                    # Let's try with a new context that attempts verification but catches errors
                    pass  # Can't easily switch context mid-connection
                except:
                    pass
                
                # Alternative: Get binary cert and parse basic info
                try:
                    bin_cert = ssock.getpeercert(binary_form=True)
                    if bin_cert:
                        result["cert_present"] = True
                        result["cert_size_bytes"] = len(bin_cert)
                        
                        # Try using cryptography library if available
                        try:
                            from cryptography import x509
                            from cryptography.hazmat.backends import default_backend
                            
                            cert = x509.load_der_x509_certificate(bin_cert, default_backend())
                            
                            # Common Name
                            cn_attrs = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                            if cn_attrs:
                                result["cert_cn"] = cn_attrs[0].value
                            
                            # Issuer
                            issuer_cn = cert.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
                            if issuer_cn:
                                result["cert_issuer"] = issuer_cn[0].value
                            
                            # SANs
                            try:
                                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                                sans = san_ext.value.get_values_for_type(x509.DNSName)
                                if sans:
                                    result["cert_sans"] = sans[:5]  # Limit to 5
                            except x509.ExtensionNotFound:
                                pass
                            
                            # Expiry
                            result["cert_not_after"] = cert.not_valid_after_utc.isoformat() if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.isoformat()
                            result["cert_not_before"] = cert.not_valid_before_utc.isoformat() if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.isoformat()
                            
                            # Self-signed check
                            if result.get("cert_cn") == result.get("cert_issuer"):
                                result["cert_self_signed"] = True
                            
                            # Days until expiry
                            try:
                                expiry = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
                                now = datetime.datetime.now(datetime.timezone.utc)
                                days_left = (expiry - now).days
                                result["cert_days_until_expiry"] = days_left
                                if days_left < 30:
                                    result["cert_warning"] = "Expiring soon!"
                            except:
                                pass
                                
                        except ImportError:
                            # cryptography not available, basic info only
                            debug("cryptography library not available for cert parsing")
                            result["cert_parsed"] = False
                        except Exception as e:
                            debug(f"Cert parse error: {e}")
                            result["cert_parsed"] = False
                            
                except Exception as e:
                    debug(f"Could not get peer cert: {e}")

        return result if result else None

    except Exception as e:
        # It's common to fail if it's not actually SSL
        return None

