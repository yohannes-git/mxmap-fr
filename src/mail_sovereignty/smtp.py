import asyncio
import logging

logger = logging.getLogger(__name__)

# Timeout de connexion TCP : 4s suffit, les serveurs lents/bloquants ne repondront pas
SMTP_CONNECT_TIMEOUT = 4.0
# Timeout de lecture : 3s — un banner SMTP arrive en <1s sur un serveur qui repond
SMTP_READ_TIMEOUT = 3.0


async def fetch_smtp_banner(
    mx_host: str,
    timeout: float = SMTP_CONNECT_TIMEOUT,
) -> dict[str, str]:
    """Connect to mx_host:25, read banner + EHLO response, QUIT.
    Returns {"banner": "...", "ehlo": "..."} or empty strings on failure.
    """
    banner = ""
    ehlo = ""
    reader = None
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(mx_host, 25), timeout=timeout
        )
        # Read 220 banner
        banner_line = await asyncio.wait_for(
            reader.readline(), timeout=SMTP_READ_TIMEOUT
        )
        banner = banner_line.decode("utf-8", errors="replace").strip()

        # Ne pas continuer si ce n'est pas un banner SMTP valide
        if not banner.startswith("2"):
            return {"banner": banner, "ehlo": ""}

        # Send EHLO
        writer.write(b"EHLO mxmap.fr\r\n")
        await writer.drain()

        # Read multi-line EHLO response (250-... continues, 250 ... ends)
        ehlo_lines = []
        while True:
            line = await asyncio.wait_for(
                reader.readline(), timeout=SMTP_READ_TIMEOUT
            )
            decoded = line.decode("utf-8", errors="replace").strip()
            if not decoded:
                break
            ehlo_lines.append(decoded)
            # SMTP multi-line: "250-..." continues, "250 ..." is last line
            if decoded[:4] != "250-":
                break
        ehlo = "\n".join(ehlo_lines)

        # Send QUIT — fire and forget, on n'attend pas la reponse
        try:
            writer.write(b"QUIT\r\n")
            await writer.drain()
        except Exception:
            pass

    except Exception as e:
        logger.debug("SMTP banner fetch failed for %s: %s", mx_host, e)
    finally:
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
    return {"banner": banner, "ehlo": ehlo}
