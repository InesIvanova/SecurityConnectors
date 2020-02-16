class ApplicationBaseException(Exception):
    def __init__(self, message=None):
        self.message = message


class ResponseNotInCorrectFormatException(ApplicationBaseException):
    pass


class MaximRequestsExceededException(ApplicationBaseException):
    pass