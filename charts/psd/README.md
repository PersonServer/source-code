# psd Helm chart

Deploys [psd](https://personserver.dev), a self-hostable AAuth Person Server,
as a single replica with a persistent volume for its SQLite database.

```sh
psd keygen --keys psd-keys.json                       # signing keys + pairwise secret, once
kubectl create secret generic psd-keys --from-file=psd-keys.json
helm install psd oci://ghcr.io/personserver/charts/psd \
  --set issuer=https://ps.example.com \
  --set keys.existingSecret=psd-keys \
  --set ingress.enabled=true --set ingress.host=ps.example.com
kubectl exec deploy/psd -- psd person add --name "Alice" --config /etc/psd/psd.json
```

What the chart enforces, and why:

- **One replica** (`replicaCount` must be 1, `strategy: Recreate`). State is
  SQLite on one volume; a second writer would corrupt it. Postgres, and with
  it horizontal scale, is planned but not built.
- **Persistence on by default.** The database is the record of which agent
  a person allowed where, and the directed identifiers services know them
  by. Losing it means every agent must be approved again and every service
  sees a new stranger. Back the volume up.
- **The issuer is permanent.** It is in every `sub` psd derives and every
  token it signs; changing it is a new server. It must be a hostname (passkeys
  do not work on IP-address origins) and the Ingress must preserve the
  `Host` header, because agents sign it and psd checks it.
- **Keys are a Secret you own.** Rotate signing keys with
  `psd keygen --rotate` outside the cluster and update the Secret; old public
  keys stay published until pruned. The `pairwise_secret` in the same file
  must never change.

Every value is documented in [`values.yaml`](values.yaml); `config.*` maps
onto psd's JSON config and `extraConfig` is deep-merged last for anything
not surfaced. The full reference is at
[personserver.dev/docs/configuration](https://personserver.dev/docs/configuration.html)
and the operator guide at
[personserver.dev/docs/install](https://personserver.dev/docs/install.html).

Adapted from the `apd` chart (MIT OR Apache-2.0),
github.com/AgentProvider/source-code.
