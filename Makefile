restart:
	docker rm -f hollo-cloudflared-1
	docker compose -f my-compose.yml build
	docker compose -f my-compose.yml down
	docker compose -f my-compose.yml up -d
