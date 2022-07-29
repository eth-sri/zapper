class AssemblySecurityException(Exception):
    """
    Exception to be raised when a proposed action threatens the integrity of the system
    """

    def __init__(self, msg: str):
        super().__init__(msg)
