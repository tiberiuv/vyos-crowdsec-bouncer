# Vyos crowdsec bouncer

Crowdsec bouncer for vyos router/firewall

The bouncer will fetch decisions from local crowdsec API and adds them to a specified vyos firewall group

### [Vyos](https://vyos.io/)
Authentication to vyos is made through apikeys

#### Manual setup
In order to make use of the blocklist, the firewall group (default CROWDSEC_BOUNCER)
needs to be added to the vyos firewall section as desired 

Example
```
rule 4 {
    action drop
    log
    source {
        group {
            network-group CROWDSEC_BOUNCER
        }
    }
 }
```

### [Crowdsec](https://docs.crowdsec.net/docs/intro/)
Authentication to crowdsec supports both apikey and MTLS
#### Limitations
Due to a [bug/limitation](https://vyos.dev/T6625) in VYOS, no more than 15k items can exist in a firewall group.
As a result we limit the origins of the decisions from crowdsec to `Origin::Crowdsec, Origin::Lists, Origin::Cscli`\
This strikes a balance between having a base of blocked ips coming from custom lists and blocking bad actors from local decisions

Once this problem is fixed we can enable the crowdsourced blocklist coming from the central api (CAPI) and allow for customizing the origins.

### CLI
```
Usage: vyos-crowdsec-bouncer [OPTIONS] --vyos-apikey <VYOS_APIKEY> --vyos-api <VYOS_API>

Options:
      --trusted-ips <TRUSTED_IPS>...
          [env: TRUSTED_IPS=]
      --update-period-secs <UPDATE_PERIOD_SECS>
          [env: UPDATE_FREQUENCY_SECS=] [default: 60]
      --vyos-apikey <VYOS_APIKEY>
          [env: VYOS_APIKEY=]
      --vyos-api <VYOS_API>
          [env: VYOS_API=]
      --crowdsec-timeout <CROWDSEC_TIMEOUT>
          [env: CROWDSEC_TIMEOUT=] [default: 10]
      --firewall-group <FIREWALL_GROUP>
          [env: FIREWALL_GROUP=] [default: CROWDSEC_BOUNCER]
      --crowdsec-api <CROWDSEC_API>
          [env: CROWDSEC_API=] [default: http://localhost:8080]
      --crowdsec-apikey <CROWDSEC_APIKEY>
          [env: CROWDSEC_APIKEY=]
      --crowdsec-root-ca-cert <CROWDSEC_ROOT_CA_CERT>
          [env: CROWDSEC_ROOT_CA_CERT=] [default: /etc/crowdsec_bouncer/certs/ca.crt]
      --crowdsec-client-cert <CROWDSEC_CLIENT_CERT>
          [env: CROWDSEC_CLIENT_CERT=] [default: /etc/crowdsec_bouncer/certs/tls.crt]
      --crowdsec-client-key <CROWDSEC_CLIENT_KEY>
          [env: CROWDSEC_CLIENT_KEY=] [default: /etc/crowdsec_bouncer/certs/tls.key]
  -h, --help
          Print help
  -V, --version
          Print version
```
