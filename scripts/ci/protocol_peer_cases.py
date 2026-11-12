"""Finite controlled-peer matrix shared by acquisition failures and execution."""


def case_matrix():
    return [(kind, mutation) for kind in ('naive-h2', 'naive-h3', 'masque-h3', 'masque-h3-on-demand')
            for mutation in ((None,) if kind.endswith('on-demand') else
                # naive-h3 has no peer-visible certificate alert over QUIC; TLS
                # rejection is covered by naive-h2 and masque-h3.
                (None, 'wrong-auth') if kind == 'naive-h3' else
                (None, 'wrong-auth', 'wrong-ca', 'wrong-sni') if kind.startswith('naive') else
                (None, 'wrong-auth', 'wrong-ca', 'wrong-sni', 'wrong-path'))]
