services:
  {service}:
    image: {image}
    container_name: {service}
    restart: unless-stopped

    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    pids_limit: 256
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64m

    networks:
      - {network}

    # No "ports:" — external access via Nginx Proxy Manager only.
    expose:
      - "{port}"

    # Variables and secrets are injected by Komodo at deploy time (no .env file).
    environment:
      TZ: "{timezone}"
      # EXAMPLE_VAR: "${{EXAMPLE_VAR}}"

    volumes:
      - {svc_path}/config:/config:ro
      - {svc_path}/data:/data

    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

networks:
  {network}:
    external: true
