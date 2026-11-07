"""Finite controlled-peer matrix shared by acquisition failures and execution."""


def case_matrix():
    return [(kind, mutation) for kind in ('naive-h2', 'naive-h3', 'masque-h3', 'masque-h3-on-demand')
            for mutation in ((None,) if kind.endswith('on-demand') else
                (None, 'wrong-auth', 'wrong-ca', 'wrong-sni') if kind.startswith('naive') else
                (None, 'wrong-auth', 'wrong-ca', 'wrong-sni', 'wrong-path'))]
