"""Machine-owned signed names must be fixed points of Replay Com_CleanName."""

from cryptography.hazmat.primitives.asymmetric import ec


def exercise(register, checks):
    for index, (requested, cleaned) in enumerate((
        ("^3Platform Color", "Platform Color"),
        ("^'Platform Lower", "Platform Lower"),
        ("^>Platform Upper", "Platform Upper"),
        ("[{Platform Markers}]", "Platform Markers"),
        ("Platform    Spaces", "Platform   Spaces"),
        ("^^Platform Carets", "Platform Carets"),
        ("Platform }[{]Boundary", "Platform Boundary"),
    )):
        signer = ec.generate_private_key(ec.SECP256R1())
        identities = []
        for name in (requested, cleaned, requested):
            identity, client = register(
                2000 + index, signer=signer, player_name=name,
                expected_name=cleaned,
            )
            identities.append(identity)
            client.close()
        assert len(set(identities)) == 1
    checks.append(
        "signed machine login returns Replay-cleaned color/bracket/space/caret names, including exposed escape boundaries, without changing the persistent player ID across relogins"
    )
