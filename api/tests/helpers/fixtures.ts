export const VALID_FIREWALL_POLICY = Buffer.from(
  JSON.stringify({
    rules: [
      {
        name: 'allow-ssh',
        protocol: 'tcp',
        port: 22,
        direction: 'ingress',
        action: 'allow',
        source: { type: 'cidr', value: '0.0.0.0/0' },
        destination: { type: 'cidr', value: '10.0.0.0/8' },
      },
    ],
  }),
);
