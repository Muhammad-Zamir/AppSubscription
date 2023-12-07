def pass_variables_into_string(string, variables):
    """Passes variables into a string."""
    # breakpoint()
    return f"{string}".format(**variables)