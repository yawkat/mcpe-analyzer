# mcpe-analyzer

radare2-based utility to parse an x86 Minecraft PE binary and extract information such as:

- Packet names
- Packet IDs
- Packet "serialization signatures" (for example `PlayerList: Byte UnsignedVarInt (mce::UUID* | PlayerListEntry*)`)
- Type serialization signatures for various structural types used in the binaries (for example `mce::UUID: RAW(8){2}`).

Information is emitted deterministically as prettified json for easy diffing.

To accomplish this, this project includes:

- A radare2 api with HTTP and spawn backends (similar to r2pipe, but with some added type safety)
- An ESIL parser
- A function graph builder
- A graph -> regex algorithm
- A regex simplification engine