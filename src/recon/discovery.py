from src.core.models import Config
from src.recon.live_hosts import probe_live_hosts
from src.recon.models import ReconCandidate
from src.recon.scoring import infer_target_profile, rank_urls
from src.recon.standardize import standardize_recon_outputs
from src.recon.subdomains import enumerate_subdomains
from src.recon.urls import collect_urls, extract_parameters


def run_recon_layer(
    scope_entries: list[str], config: Config, *, skip_crtsh: bool = False
) -> dict[str, object]:
    subdomains = enumerate_subdomains(scope_entries, vars(config), skip_crtsh)
    _, live_hosts = probe_live_hosts(subdomains, config)
    urls = collect_urls(live_hosts, scope_entries, config)
    parameters = extract_parameters(urls)
    profile = infer_target_profile(urls)
    ranked_urls = rank_urls(
        urls,
        filters=config.filters,
        scoring=config.scoring,
        mode=config.mode,
        profile=profile,
        history_feedback=None,
    )
    candidates: list[ReconCandidate] = standardize_recon_outputs(
        subdomains=subdomains,
        live_hosts=live_hosts,
        urls=urls,
        ranked_urls=ranked_urls,
        parameters=parameters,
    )
    return {
        "subdomains": subdomains,
        "live_hosts": live_hosts,
        "urls": urls,
        "parameters": parameters,
        "ranked_urls": ranked_urls,
        "candidates": candidates,
    }
