class Path(object):
    def __init__(self, src_ip, dst_ip):
        """

        :param src_ip: From IP
        :type src_ip: str
        :param dst_ip: To IP
        :type dst_ip: str
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.fw = []
        self.bw = []

