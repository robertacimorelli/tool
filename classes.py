class AEGRBACPolicy:
    def __init__(self):
        self.AUser = set()
        self.AR = set()
        self.AUA = set()
        self.RP = set()
        self.DR = set()
        self.RPDRA = set()
        self.AssignRPDR = set()
        self.RevokeRPDR = set()
        self.Query = set()

    # Getter methods
    def get_auser(self):
        return self.AUser

    def get_ar(self):
        return self.AR

    def get_aua(self):
        return self.AUA

    def get_rp(self):
        return self.RP

    def get_dr(self):
        return self.DR

    def get_rpdra(self):
        return self.RPDRA

    def get_assign_rpdr(self):
        return self.AssignRPDR

    def get_revoke_rpdr(self):
        return self.RevokeRPDR

    def get_query(self):
        return self.Query

    def get_all_attributes(self):
        return {
            'AUser': self.AUser,
            'AR': self.AR,
            'AUA': self.AUA,
            'RP': self.RP,
            'DR': self.DR,
            'RPDRA': self.RPDRA,
            'AssignRPDR': self.AssignRPDR,
            'RevokeRPDR': self.RevokeRPDR,
            'Query': self.Query
        }

    # Setter methods
    def set_auser(self, auser):
        self.AUser = auser

    def set_ar(self, ar):
        self.AR = ar

    def set_aua(self, aua):
        self.AUA = aua

    def set_rp(self, rp):
        self.RP = rp

    def set_dr(self, dr):
        self.DR = dr

    def set_rpdra(self, rpdra):
        self.RPDRA = rpdra

    def set_assign_rpdr(self, assign_rpdr):
        self.AssignRPDR = assign_rpdr

    def set_revoke_rpdr(self, revoke_rpdr):
        self.RevokeRPDR = revoke_rpdr

    def set_query(self, query):
        self.Query = query


class ARBACPolicy:
    def __init__(self):
        self.U = set()
        self.UA = set()
        self.R = set()
        self.can_assign = set()
        self.can_revoke = set()
        self.query = set()

    # Getter methods
    def get_u(self):
        return self.U

    def get_ua(self):
        return self.UA

    def get_r(self):
        return self.R

    def get_can_assign(self):
        return self.can_assign

    def get_can_revoke(self):
        return self.can_revoke

    def get_query(self):
        return self.query

    def get_all_attributes(self):
        return {
            'U': self.U,
            'R': self.R,
            'UA': self.UA,
            'can_assign': self.can_assign,
            'can_revoke': self.can_revoke
        }

    # Setter methods
    def set_u(self, u):
        self.U = u

    def set_ua(self, ua):
        self.UA = ua

    def set_r(self, r):
        self.R = r

    def set_can_assign(self, can_assign):
        self.can_assign = can_assign

    def set_can_revoke(self, can_revoke):
        self.can_revoke = can_revoke

    def set_query(self, query):
        self.query = query
