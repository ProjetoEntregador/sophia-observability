<h1 align="center" style="font-weight: bold;">Serviço de Observabilidade</h1>

Este serviço tem por objetivo centralizar a visualização de dados coletados dos serviços de Notificação, Medicamentos e Farmácia, permitindo o acompanhamento em tempo real de métricas coletadas dos bancos de dados, logs e eventos de auditoria.

<h2>🛠️ Funcionalidades</h2>

- Dashboard geral de auditoria e alertas
- Dashboards específicas para acompanhamento do banco de cada um dos serviços
- Acompanhamento dos logs de cada banco
- Acompanhamento de métricas customizadas de cada banco

<h2>💻 Tecnologias</h2>

- Python
- Prometheus
- Grafana
- Loki
- PostgreSQL

<h2>🚀 Instalação</h2>

<h3>Pré-requisitos</h3>

- Git
- Docker & Docker Compose

<h3>Clonar</h3>

```bash
git clone https://github.com/ProjetoEntregador/sophia-observability.git
cd sophia-observability
```

<h3>Configurar variáveis .env</h2>

Renomeie o arquivo `.env.example` para `.env`

<h3>Inicializando</h3>

```bash
docker-compose up -d
```

Para visualizar a dashboard, acesse http://localhost:3333
