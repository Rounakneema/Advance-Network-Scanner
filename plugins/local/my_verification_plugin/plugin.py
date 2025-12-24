def run(context):
    """
    Main entry point for the plugin.
    
    Args:
        context (dict): Contains 'target', 'port', 'service', 'banner', 'details'.
    
    Returns:
        dict: A dictionary of findings or details to merge into the host info.
              Return None or empty dict if nothing found.
    """
    target = context['target']
    port = context['port']
    service = context.get('service', 'unknown')
    
    # checking logic here
    # ...

    return {
        "manual_check": f"Executed on {target}:{port} ({service})"
    }
