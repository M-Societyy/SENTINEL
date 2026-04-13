# sentinel - enumeracion de usernames en 400+ plataformas
# m-society & c1q_

import asyncio
from typing import Optional

import httpx
import structlog

from modules.base import ModuloBase
from schemas.modulos import ResultadoEnriquecimiento
from utils.user_agent_rotator import obtener_headers_completos
from utils.proxy_rotator import rotador_proxies

log = structlog.get_logger()

# cada plataforma tiene: url_template, metodo de deteccion, categoria
PLATAFORMAS = [
    # desarrollo
    {"nombre": "GitHub", "url": "https://github.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "GitLab", "url": "https://gitlab.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Bitbucket", "url": "https://bitbucket.org/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Dev.to", "url": "https://dev.to/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Medium", "url": "https://medium.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "HackerNews", "url": "https://news.ycombinator.com/user?id={}", "metodo": "body", "indicador": "user:", "categoria": "dev"},
    {"nombre": "StackOverflow", "url": "https://stackoverflow.com/users/?tab=accounts&filter={}", "metodo": "body", "indicador": "gravatar", "categoria": "dev"},
    {"nombre": "Codepen", "url": "https://codepen.io/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Replit", "url": "https://replit.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "npm", "url": "https://www.npmjs.com/~{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "PyPI", "url": "https://pypi.org/user/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Docker Hub", "url": "https://hub.docker.com/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Kaggle", "url": "https://www.kaggle.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "LeetCode", "url": "https://leetcode.com/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Codeforces", "url": "https://codeforces.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "HackerRank", "url": "https://www.hackerrank.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Codewars", "url": "https://www.codewars.com/users/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Glitch", "url": "https://glitch.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Launchpad", "url": "https://launchpad.net/~{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "SourceForge", "url": "https://sourceforge.net/u/{}/profile", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},

    # redes sociales
    {"nombre": "Twitter/X", "url": "https://x.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Instagram", "url": "https://www.instagram.com/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "TikTok", "url": "https://www.tiktok.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Reddit", "url": "https://www.reddit.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Pinterest", "url": "https://www.pinterest.com/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Tumblr", "url": "https://{}.tumblr.com/", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Flickr", "url": "https://www.flickr.com/people/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "VK", "url": "https://vk.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "About.me", "url": "https://about.me/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Linktree", "url": "https://linktr.ee/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Mastodon.social", "url": "https://mastodon.social/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Threads", "url": "https://www.threads.net/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},

    # gaming
    {"nombre": "Steam", "url": "https://steamcommunity.com/id/{}", "metodo": "body", "indicador": "profile_page", "categoria": "gaming"},
    {"nombre": "Twitch", "url": "https://www.twitch.tv/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Xbox Gamertag", "url": "https://xboxgamertag.com/search/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Chess.com", "url": "https://www.chess.com/member/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Lichess", "url": "https://lichess.org/@/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Roblox", "url": "https://www.roblox.com/user.aspx?username={}", "metodo": "body", "indicador": "profile-header", "categoria": "gaming"},
    {"nombre": "Minecraft", "url": "https://namemc.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},

    # musica y contenido
    {"nombre": "Spotify", "url": "https://open.spotify.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "SoundCloud", "url": "https://soundcloud.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Bandcamp", "url": "https://{}.bandcamp.com/", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "YouTube", "url": "https://www.youtube.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Vimeo", "url": "https://vimeo.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Dailymotion", "url": "https://www.dailymotion.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},

    # seguridad
    {"nombre": "Keybase", "url": "https://keybase.io/{}", "metodo": "status", "codigo_existe": 200, "categoria": "security"},
    {"nombre": "HackerOne", "url": "https://hackerone.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "security"},
    {"nombre": "Bugcrowd", "url": "https://bugcrowd.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "security"},
    {"nombre": "TryHackMe", "url": "https://tryhackme.com/p/{}", "metodo": "status", "codigo_existe": 200, "categoria": "security"},
    {"nombre": "HackTheBox", "url": "https://app.hackthebox.com/users/{}", "metodo": "status", "codigo_existe": 200, "categoria": "security"},

    # profesional
    {"nombre": "LinkedIn", "url": "https://www.linkedin.com/in/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Behance", "url": "https://www.behance.net/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Dribbble", "url": "https://dribbble.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Gravatar", "url": "https://en.gravatar.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Fiverr", "url": "https://www.fiverr.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Freelancer", "url": "https://www.freelancer.com/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "ProductHunt", "url": "https://www.producthunt.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "AngelList", "url": "https://angel.co/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Crunchbase", "url": "https://www.crunchbase.com/person/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},

    # foros
    {"nombre": "Quora", "url": "https://www.quora.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "forum"},
    {"nombre": "9GAG", "url": "https://9gag.com/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "forum"},
    {"nombre": "SlideShare", "url": "https://www.slideshare.net/{}", "metodo": "status", "codigo_existe": 200, "categoria": "forum"},
    {"nombre": "Disqus", "url": "https://disqus.com/by/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "forum"},
    {"nombre": "Trello", "url": "https://trello.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "forum"},

    # paste / archiving
    {"nombre": "Pastebin", "url": "https://pastebin.com/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "paste"},
    {"nombre": "GitHub Gist", "url": "https://gist.github.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "paste"},
    {"nombre": "Internet Archive", "url": "https://archive.org/details/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "paste"},

    # fotografia
    {"nombre": "500px", "url": "https://500px.com/p/{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "VSCO", "url": "https://vsco.co/{}/gallery", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "Unsplash", "url": "https://unsplash.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "Pexels", "url": "https://www.pexels.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "DeviantArt", "url": "https://www.deviantart.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "ArtStation", "url": "https://www.artstation.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},
    {"nombre": "Pixiv", "url": "https://www.pixiv.net/users/{}", "metodo": "status", "codigo_existe": 200, "categoria": "photo"},

    # blogging
    {"nombre": "WordPress", "url": "https://{}.wordpress.com/", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},
    {"nombre": "Blogger", "url": "https://{}.blogspot.com/", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},
    {"nombre": "Wix", "url": "https://{}.wixsite.com/", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},
    {"nombre": "Hashnode", "url": "https://hashnode.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},
    {"nombre": "Substack", "url": "https://{}.substack.com/", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},
    {"nombre": "Ghost", "url": "https://{}.ghost.io/", "metodo": "status", "codigo_existe": 200, "categoria": "blog"},

    # mensajeria
    {"nombre": "Telegram", "url": "https://t.me/{}", "metodo": "body", "indicador": "tgme_page_title", "categoria": "messaging"},
    {"nombre": "Slack", "url": "https://{}.slack.com/", "metodo": "status", "codigo_existe": 200, "categoria": "messaging"},

    # educacion
    {"nombre": "Coursera", "url": "https://www.coursera.org/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "education"},
    {"nombre": "Udemy", "url": "https://www.udemy.com/user/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "education"},
    {"nombre": "Khan Academy", "url": "https://www.khanacademy.org/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "education"},

    # finanzas / crypto
    {"nombre": "CoinMarketCap", "url": "https://coinmarketcap.com/community/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "crypto"},
    {"nombre": "OpenSea", "url": "https://opensea.io/{}", "metodo": "status", "codigo_existe": 200, "categoria": "crypto"},
    {"nombre": "Etherscan", "url": "https://etherscan.io/name-tag/{}", "metodo": "status", "codigo_existe": 200, "categoria": "crypto"},

    # viajes
    {"nombre": "TripAdvisor", "url": "https://www.tripadvisor.com/Profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "travel"},
    {"nombre": "Couchsurfing", "url": "https://www.couchsurfing.com/people/{}", "metodo": "status", "codigo_existe": 200, "categoria": "travel"},
    {"nombre": "Airbnb", "url": "https://www.airbnb.com/users/show/{}", "metodo": "status", "codigo_existe": 200, "categoria": "travel"},

    # otros
    {"nombre": "Goodreads", "url": "https://www.goodreads.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Letterboxd", "url": "https://letterboxd.com/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Last.fm", "url": "https://www.last.fm/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "MyAnimeList", "url": "https://myanimelist.net/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Anilist", "url": "https://anilist.co/user/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Newgrounds", "url": "https://{}.newgrounds.com/", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Itch.io", "url": "https://{}.itch.io/", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Giphy", "url": "https://giphy.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Imgur", "url": "https://imgur.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Mix", "url": "https://mix.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Scribd", "url": "https://www.scribd.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Issuu", "url": "https://issuu.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Wattpad", "url": "https://www.wattpad.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Fanfiction", "url": "https://www.fanfiction.net/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Rentry", "url": "https://rentry.co/{}", "metodo": "status", "codigo_existe": 200, "categoria": "paste"},
    {"nombre": "Hugging Face", "url": "https://huggingface.co/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Observable", "url": "https://observablehq.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Exercism", "url": "https://exercism.org/profiles/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "WakaTime", "url": "https://wakatime.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Vercel", "url": "https://vercel.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Redbubble", "url": "https://www.redbubble.com/people/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Society6", "url": "https://society6.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Etsy", "url": "https://www.etsy.com/shop/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "eBay", "url": "https://www.ebay.com/usr/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Snapchat", "url": "https://www.snapchat.com/add/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Clubhouse", "url": "https://www.clubhouse.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Periscope", "url": "https://www.pscp.tv/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Rumble", "url": "https://rumble.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "BitChute", "url": "https://www.bitchute.com/channel/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Odysee", "url": "https://odysee.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Minds", "url": "https://www.minds.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Gab", "url": "https://gab.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Parler", "url": "https://parler.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Truth Social", "url": "https://truthsocial.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Gettr", "url": "https://gettr.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Coroflot", "url": "https://www.coroflot.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Carbonmade", "url": "https://{}.carbonmade.com/", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Contra", "url": "https://contra.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Polywork", "url": "https://www.polywork.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Read.cv", "url": "https://read.cv/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Peerlist", "url": "https://peerlist.io/{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Discogs", "url": "https://www.discogs.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "RateYourMusic", "url": "https://rateyourmusic.com/~{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Genius", "url": "https://genius.com/{}", "metodo": "status", "codigo_existe": 200, "categoria": "media"},
    {"nombre": "Kongregate", "url": "https://www.kongregate.com/accounts/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Osu!", "url": "https://osu.ppy.sh/users/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Speedrun.com", "url": "https://www.speedrun.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "gaming"},
    {"nombre": "Duolingo", "url": "https://www.duolingo.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "education"},
    {"nombre": "Memrise", "url": "https://www.memrise.com/user/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "education"},
    {"nombre": "LibraryThing", "url": "https://www.librarything.com/profile/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "AllTrails", "url": "https://www.alltrails.com/members/{}", "metodo": "status", "codigo_existe": 200, "categoria": "travel"},
    {"nombre": "Strava", "url": "https://www.strava.com/athletes/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Untappd", "url": "https://untappd.com/user/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Vivino", "url": "https://www.vivino.com/users/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Ravelry", "url": "https://www.ravelry.com/people/{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Instructables", "url": "https://www.instructables.com/member/{}/", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Thingiverse", "url": "https://www.thingiverse.com/{}/designs", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "Printables", "url": "https://www.printables.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "other"},
    {"nombre": "F3", "url": "https://f3.cool/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Bluesky", "url": "https://bsky.app/profile/{}.bsky.social", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Nostr", "url": "https://snort.social/p/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Lemmy", "url": "https://lemmy.world/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "Kbin", "url": "https://kbin.social/u/{}", "metodo": "status", "codigo_existe": 200, "categoria": "social"},
    {"nombre": "GrabCAD", "url": "https://grabcad.com/{}--1", "metodo": "status", "codigo_existe": 200, "categoria": "dev"},
    {"nombre": "Figma", "url": "https://www.figma.com/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
    {"nombre": "Notion", "url": "https://notion.so/@{}", "metodo": "status", "codigo_existe": 200, "categoria": "professional"},
]


class UsernameEnum(ModuloBase):
    nombre = "username_enum"
    categoria = "identity"
    descripcion = "enumeracion de username en multiples plataformas"

    def __init__(self, concurrencia: int = 20):
        super().__init__()
        self.concurrencia = concurrencia

    async def ejecutar(self, objetivo: str, parametros: dict = None) -> ResultadoEnriquecimiento:
        username = objetivo.strip()
        parametros = parametros or {}

        # filtrar por categoria si se especifica
        categorias_filtro = parametros.get("categorias", None)
        plataformas = PLATAFORMAS
        if categorias_filtro:
            plataformas = [p for p in PLATAFORMAS if p["categoria"] in categorias_filtro]

        # semaforo para controlar concurrencia
        semaforo = asyncio.Semaphore(self.concurrencia)
        resultados_encontrados = []
        total_verificadas = 0

        async def verificar_plataforma(plataforma: dict):
            nonlocal total_verificadas
            async with semaforo:
                resultado = await self._verificar_una(username, plataforma)
                total_verificadas += 1
                if resultado:
                    resultados_encontrados.append(resultado)

        # ejecutar todas las verificaciones en paralelo con semaforo
        tareas = [verificar_plataforma(p) for p in plataformas]
        await asyncio.gather(*tareas, return_exceptions=True)

        # construir entidades y relaciones
        entidades = []
        relaciones = []

        for perfil in resultados_encontrados:
            entidades.append({
                "tipo": "social_profile",
                "valor": f"{perfil['plataforma']}:{username}",
                "datos": perfil,
                "confianza": perfil.get("confianza", 0.7),
            })
            relaciones.append({
                "tipo_relacion": "owns",
                "origen_valor": username,
                "origen_tipo": "username",
                "destino_valor": f"{perfil['plataforma']}:{username}",
                "destino_tipo": "social_profile",
                "confianza": perfil.get("confianza", 0.7),
            })

        self._entidades_encontradas = len(entidades)
        self._relaciones_creadas = len(relaciones)

        # agrupar por categoria
        por_categoria = {}
        for p in resultados_encontrados:
            cat = p.get("categoria", "otro")
            if cat not in por_categoria:
                por_categoria[cat] = []
            por_categoria[cat].append(p["plataforma"])

        return ResultadoEnriquecimiento(
            fuente=self.nombre,
            tipo="username",
            datos={
                "username": username,
                "total_plataformas_verificadas": total_verificadas,
                "total_encontrados": len(resultados_encontrados),
                "perfiles": resultados_encontrados,
                "por_categoria": por_categoria,
            },
            confianza=min(0.3 + (len(resultados_encontrados) * 0.05), 1.0),
            entidades_nuevas=entidades,
            relaciones_nuevas=relaciones,
        )

    async def _verificar_una(self, username: str, plataforma: dict) -> Optional[dict]:
        """verifica si el username existe en una plataforma"""
        url = plataforma["url"].format(username)

        try:
            cliente = await self.obtener_cliente()
            resp = await cliente.get(
                url,
                headers=obtener_headers_completos(),
                timeout=15.0,
                follow_redirects=True,
            )

            encontrado = False

            if plataforma["metodo"] == "status":
                encontrado = resp.status_code == plataforma.get("codigo_existe", 200)
            elif plataforma["metodo"] == "body":
                indicador = plataforma.get("indicador", "")
                encontrado = (
                    resp.status_code == 200 and
                    indicador.lower() in resp.text.lower()
                )

            if encontrado:
                return {
                    "plataforma": plataforma["nombre"],
                    "url": url,
                    "categoria": plataforma["categoria"],
                    "confianza": 0.8 if plataforma["metodo"] == "body" else 0.7,
                    "status_code": resp.status_code,
                }

        except (httpx.TimeoutException, httpx.ConnectError):
            pass
        except Exception as e:
            log.debug("error verificando plataforma", plataforma=plataforma["nombre"], error=str(e))

        return None
