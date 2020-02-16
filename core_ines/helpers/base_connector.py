from abc import ABCMeta, abstractmethod


class BaseConnector:
    __metaclass__ = ABCMeta
    def __init__(self, path):
        self.path = path

    @abstractmethod
    def analyze(self): NotImplementedError


class ConnectorResult:
    def __init__(self, result):
        self.result = result