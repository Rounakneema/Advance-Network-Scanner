def run(context):
    """
    Sample plugin that just returns a static finding for verification.
    In a real plugin, this would make a request to context['target'].
    """
    debug = context.get('debug', lambda x: None)
    debug("Running sample validation...")
    target = context['target']
    port = context['port']
    
    # Simulate logic
    return {
        "headers_check": "Verified (Sample Plugin)",
        "plugin_message": f"Hello from {target}:{port}"
    }
