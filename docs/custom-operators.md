# Custom operators

The client can load custom body and head XModels from a native Replay fastfile.
The package is embedded in the executable and installed with its locale
companions. It loads after its MP shader and ragdoll dependencies, sharing the
MP common unload group. Local deployment installs the same files
alongside the executable, PDB and MAP.

Select an operator with the archived `dw_customOperator` dvar. The stock
Operators page has no added selection controls:

| Command | Operator |
| --- | --- |
| `dw_customOperator 0` | Equipped stock operator |
| `dw_customOperator 1` | Nicky |
| `dw_customOperator 2` | Black Ops 2 SEAL assault soldier |

The selection is a local cosmetic preference. Native head/body table lookups
resolve the custom IDs for the local frontend preview. In a match, the native
client model selector applies the custom pair to the local player's appearance.
Uploaded playercards, server models, hit detection and replicated customization
keep the equipped stock operator. Other players see that stock operator and do
not need the custom package. No shared network model-name table is added.
Spectated players and killcams retain their normal appearance.
Party-lobby previews substitute only the local member's copied appearance data.
Custom humanoids use the native male squad walk cycles, including the shield
variant, instead of the unknown-model idle fallback. No new profile enum values
are written to the server or to other clients.
First-person viewhands remain stock. The client log records selection and
package readiness.
First-person legs resolve the selected body through their native build and cache
checks. The cached legs model is compared with the selected source model so a
changed selection rebuilds it once, and an unchanged selection reuses it.
Package bindings are refreshed through the native validator after the operator
zone and its dependencies finish loading, before the selection becomes active.

## Import and build

Run the tools from `E:\DW\IW8`. Source models and generated packages are under
`data/custom-operators`; imported game assets are not included in the public
recompiler repository.

1. `tools/build-custom-operator-model.ps1` builds the native model writer using
   the reviewed Replay zonetool sources.
2. `tools/import-custom-operator-model.py` reads a skinned GLB, maps its bones to
   the exported Replay skeleton, retargets the bind geometry, and separates the
   body and head. Pass `--source`, `--native-skeleton`, `--material-donor`,
   `--kind nicky|cod`, `--id` and `--output`.
3. `tools/prepare-custom-operator-package.py` accepts repeated `--model-input`
   arguments. It writes the native FF/FP, rereads both through the original
   Replay loader, and generates the embedded package header and manifest.
4. `python -B tools/build-dw-client.py --validate-only` freezes current sources,
   builds the client and symbols, and runs the linked-image checks without
   publishing a release.
5. `python -B tools/deploy-dw-client-local.py --job JOB` installs a verified job. The
   installer retains replaced files for rollback and leaves the INI and maps
   outside its transaction.

The package manifest defines paired model names. Native registration reserves
primary IDs 60000 and 60001 and excludes those explicit selections from random
operator pools. Adding another operator requires extending the manifest and
the selection range together.

## Model constraints

The body retains all 97 regular and 71 client bones from the native human
skeleton, including fingers, attachment tags and IK bones. Each head retains
seven weighted or ancestor bones. The 104 regular bones leave 150 entries below
the native regular-bone limit for weapons and accessories. Client bones have
separate native counts and animation masks.
Triangle winding follows Replay's native front-face order. Animated surfaces
share an origin-centered packing envelope so movement does not clamp vertices
to their bind-pose material bounds.
Weighted models carry the native skinned-surface flag in their serialized
XModel headers; resident models cannot rely on transient surface replacement
to derive that flag later.

Replay's GPU skinning uses eight influence-count tiers. Each influence is one
little-endian DWORD: bone index in the low 16 bits and weight in the high 16
bits. Within a tier, the first influence for every vertex comes first, followed
by the second influence for every vertex, and so on. The primary weight is the
remainder after the other weights and is stored as zero. The converter accepts
up to four influences from XSE and writes this native block layout.

The original CPU skinning routines read a different, interleaved layout. They
are not a format oracle for the GPU stream. Package validation checks every
serialized influence against the source using the addressing in Replay's
`cs_skinning_unified_main` shader, including bone ranges and weight sums.

The current imports use native soldier shading with the source diffuse
textures. Finger joints map to their native client-bone counterparts. Foreign
facial and helper bones without a native counterpart inherit their nearest
mapped ancestor. First-person custom arms are not part of these body/head imports.
Hand meshes use native segment lengths and palm-plane orientation when
retargeting the source bind pose. The native skeleton and animation data are
preserved.

The package reader, skin-weight checks and compiled tests establish asset and
integration compatibility. In-game animation, equipped weapons, ragdolls and
remote appearance must also be checked in the game.
