# fediverse-gateway

A thin ActivityPub gateway that makes Warpnet users discoverable and followable
from Mastodon / the Fediverse. It is agnostic to node, user, and network: it
joins Warpnet through the network's bootstrap nodes and resolves any requested
user via the public routes.

> [!WARNING]  
> The gateway was entirely vibecoded because the ActivityPub feature is nice to
> have but not necessary for Warpnet. Besides, ActivityPub is considered obsolete
> and goes against Warpnet's principles.
