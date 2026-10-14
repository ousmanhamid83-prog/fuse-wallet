#!/usr/bin/env python3
"""Moteur de mandat — le verrou d'autorisation de Tasko Defense.

Un mandat est décrit dans un fichier YAML lisible par machine (voir
``mandats/exemple.mandat.yaml``) qui reflète le mandat juridique signé. Avant
tout test, les outils appellent :func:`autoriser` : si le mandat ne couvre pas
la cible, le moment, le type de test ou l'IP source, la fonction refuse, avec
une raison explicite. Rien n'est scanné sur un refus.

Règles non négociables, quelles que soient les cases cochées dans le mandat :
  - un mandat NON signé n'autorise rien ;
  - un mandat expiré (ou pas encore valide) n'autorise rien ;
  - le test réseau exige un hébergement dédié (sinon on scanne l'infra d'un tiers) ;
  - l'exploitation (pentest) exige l'Annexe D explicitement signée.

Ce module ne dépend que de la bibliothèque standard + PyYAML. Il ne contacte
aucun réseau et n'exécute aucun outil : il décide, point.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import ipaddress
import re
from typing import Iterable
from zoneinfo import ZoneInfo

import yaml

# Types de tests reconnus et leur clé dans le mandat (section tests_autorises).
TYPES_TEST = (
    "decouverte",        # cartographie / scan de ports
    "scan_web",          # Nuclei, WPScan, ZAP passif
    "scan_reseau",       # Nmap (exige hébergement dédié)
    "test_authentifie",  # ZAP authentifié via compte de test
    "exploitation",      # pentest avec exploitation (exige Annexe D)
    "ingenierie_sociale",
)


class MandatError(Exception):
    """Mandat illisible, incomplet ou incohérent (défaut de configuration)."""


@dataclasses.dataclass(frozen=True)
class Decision:
    """Résultat d'une demande d'autorisation."""

    autorise: bool
    raison: str
    reference: str = ""

    def __bool__(self) -> bool:  # permet `if autoriser(...):`
        return self.autorise


@dataclasses.dataclass
class Fenetre:
    jours: tuple[int, ...]   # 1 = lundi … 7 = dimanche (ISO)
    debut: _dt.time
    fin: _dt.time

    def contient(self, moment: _dt.datetime) -> bool:
        """Le moment (déjà exprimé dans le fuseau du mandat) est-il dans la fenêtre ?

        Gère une fenêtre qui franchit minuit (ex. 22:00 → 05:00).
        """
        if moment.isoweekday() not in self.jours:
            return False
        t = moment.time()
        if self.debut <= self.fin:
            return self.debut <= t <= self.fin
        # franchit minuit
        return t >= self.debut or t <= self.fin


@dataclasses.dataclass
class Mandat:
    reference: str
    signe: bool
    valide_du: _dt.date
    valide_au: _dt.date
    fuseau: str
    fenetres: list[Fenetre]
    ip_source: list[str]
    domaines: list[str]
    ips: list[str]
    heberge_dedie: bool
    exclusions_domaines: list[str]
    exclusions_ips: list[str]
    tests_autorises: dict[str, bool]
    annexe_d_signee: bool
    brut: dict
    problemes: list[str] = dataclasses.field(default_factory=list)

    # ------------------------------------------------------------------ chargement
    @classmethod
    def charger(cls, chemin: str) -> "Mandat":
        try:
            with open(chemin, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except FileNotFoundError as e:
            raise MandatError(f"mandat introuvable : {chemin}") from e
        except yaml.YAMLError as e:
            raise MandatError(f"YAML invalide dans {chemin} : {e}") from e
        if not isinstance(data, dict) or "mandat" not in data:
            raise MandatError(f"{chemin} : clé racine 'mandat' manquante")
        return cls.depuis_dict(data["mandat"], chemin)

    @classmethod
    def depuis_dict(cls, m: dict, origine: str = "<dict>") -> "Mandat":
        signe = bool(m.get("signe", False))
        problemes: list[str] = []

        # En mode « non signé » (gabarit en cours), on tolère les champs non
        # remplis : le mandat se charge et refusera de toute façon tout test
        # (verrou signature). Dès que signe=true, tout champ invalide lève une
        # MandatError : impossible de lancer un test sur un mandat mal rempli.
        def souci(msg: str):
            if signe:
                raise MandatError(f"{origine} : {msg}")
            problemes.append(msg)

        def req(cle):
            if cle not in m:
                souci(f"champ obligatoire manquant : {cle}")
                return None
            return m[cle]

        try:
            valide_du = _as_date(req("valide_du"))
            valide_au = _as_date(req("valide_au"))
        except (ValueError, TypeError) as e:
            souci(f"date invalide ({e})")
            valide_du = valide_au = _dt.date(1970, 1, 1)  # sentinelle : refus garanti
        if valide_du is None or valide_au is None:
            valide_du = valide_au = _dt.date(1970, 1, 1)
        if valide_au < valide_du:
            souci(f"valide_au ({valide_au}) est avant valide_du ({valide_du})")
            valide_du = valide_au = _dt.date(1970, 1, 1)

        fuseau = str(m.get("fuseau", "UTC"))
        try:
            ZoneInfo(fuseau)
        except Exception as e:  # noqa: BLE001 - zoneinfo lève des types variés
            souci(f"fuseau inconnu : {fuseau} ({e})")
            fuseau = "UTC"

        try:
            fenetres = [_parse_fenetre(f, origine) for f in (m.get("fenetres") or [])]
        except MandatError as e:
            if signe:
                raise
            problemes.append(str(e))
            fenetres = []

        perim = m.get("perimetre") or {}
        domaines = [_norm_domaine(d) for d in (perim.get("domaines") or [])]
        ips = _reseaux_valides(perim.get("ips"), souci, "perimetre.ips")

        excl = m.get("exclusions") or {}
        exclusions_domaines = [_norm_domaine(d) for d in (excl.get("domaines") or [])]
        exclusions_ips = _reseaux_valides(excl.get("ips"), souci, "exclusions.ips")

        tests = {t: bool((m.get("tests_autorises") or {}).get(t, False)) for t in TYPES_TEST}

        ip_source = _reseaux_valides(m.get("ip_source"), souci, "ip_source")

        return cls(
            reference=str(m.get("reference", "")),
            signe=bool(m.get("signe", False)),
            valide_du=valide_du,
            valide_au=valide_au,
            fuseau=fuseau,
            fenetres=fenetres,
            ip_source=ip_source,
            domaines=domaines,
            ips=ips,
            heberge_dedie=bool(perim.get("heberge_dedie", False)),
            exclusions_domaines=exclusions_domaines,
            exclusions_ips=exclusions_ips,
            tests_autorises=tests,
            annexe_d_signee=bool(m.get("annexe_d_signee", False)),
            brut=m,
            problemes=problemes,
        )

    # ------------------------------------------------------------------ périmètre
    def cible_dans_perimetre(self, cible: str) -> tuple[bool, str]:
        """La cible (URL, domaine ou IP) est-elle dans le périmètre et non exclue ?"""
        hote = extraire_hote(cible)
        if not hote:
            return False, f"cible illisible : {cible!r}"

        ip = _comme_ip(hote)
        if ip is not None:
            # Cible IP : doit tomber dans une plage du périmètre, hors exclusions.
            for ex in self.exclusions_ips:
                if _ip_dans(ip, ex):
                    return False, f"{hote} est explicitement exclu (exclusions.ips: {ex})"
            for plage in self.ips:
                if _ip_dans(ip, plage):
                    return True, f"{hote} ∈ périmètre IP {plage}"
            return False, f"{hote} hors du périmètre IP (§2.1)"

        # Cible domaine.
        for ex in self.exclusions_domaines:
            if _domaine_correspond(hote, ex):
                return False, f"{hote} est explicitement exclu (exclusions.domaines: {ex})"
        for d in self.domaines:
            if _domaine_correspond(hote, d):
                return True, f"{hote} ∈ périmètre domaine {d}"
        return False, f"{hote} hors du périmètre domaine (§2.1)"


def _parse_fenetre(f: dict, origine: str) -> Fenetre:
    try:
        jours = tuple(int(j) for j in (f.get("jours") or [1, 2, 3, 4, 5, 6, 7]))
        if not jours or any(j < 1 or j > 7 for j in jours):
            raise ValueError("jours doit être une liste d'entiers 1..7")
        return Fenetre(jours=jours, debut=_as_time(f["debut"]), fin=_as_time(f["fin"]))
    except (KeyError, ValueError, TypeError) as e:
        raise MandatError(f"{origine} : fenêtre invalide ({e})") from e


# ---------------------------------------------------------------- autorisation
def autoriser(
    mandat: Mandat,
    cible: str,
    type_test: str,
    *,
    moment: _dt.datetime | None = None,
    ip_source: str | None = None,
) -> Decision:
    """Décide si ``type_test`` peut viser ``cible`` sous ``mandat``, maintenant.

    :param moment: instant du test (aware de préférence). None => maintenant (UTC).
    :param ip_source: IP d'où part le test ; comparée à ip_source du mandat si fournie.
    """
    ref = mandat.reference

    if type_test not in TYPES_TEST:
        return Decision(False, f"type de test inconnu : {type_test!r}", ref)

    # 1. Signature (verrou absolu).
    if not mandat.signe:
        return Decision(False, "mandat NON signé : aucun test autorisé", ref)

    # 2. Validité temporelle (dates).
    moment = _moment_aware(moment)
    local = moment.astimezone(ZoneInfo(mandat.fuseau))
    jour = local.date()
    if jour < mandat.valide_du:
        return Decision(False, f"mandat pas encore valide (début {mandat.valide_du})", ref)
    if jour > mandat.valide_au:
        return Decision(False, f"mandat expiré (fin {mandat.valide_au})", ref)

    # 3. Fenêtre horaire.
    if mandat.fenetres and not any(fen.contient(local) for fen in mandat.fenetres):
        return Decision(
            False,
            f"hors fenêtre horaire (heure locale {local:%Y-%m-%d %H:%M} {mandat.fuseau})",
            ref,
        )

    # 4. Type de test autorisé par le mandat.
    if not mandat.tests_autorises.get(type_test, False):
        return Decision(False, f"type de test non autorisé par le mandat : {type_test}", ref)

    # 5. Règles renforcées selon le type.
    if type_test == "scan_reseau" and not mandat.heberge_dedie:
        return Decision(
            False,
            "scan_reseau interdit : hébergement non déclaré dédié (risque d'infra mutualisée tierce)",
            ref,
        )
    if type_test == "exploitation" and not mandat.annexe_d_signee:
        return Decision(False, "exploitation interdite sans Annexe D signée", ref)

    # 6. Périmètre.
    ok, raison = mandat.cible_dans_perimetre(cible)
    if not ok:
        return Decision(False, raison, ref)

    # 7. IP source déclarée (si on peut la vérifier).
    if ip_source is not None and mandat.ip_source:
        if not any(_ip_dans(_comme_ip(ip_source), p) for p in mandat.ip_source
                   if _comme_ip(ip_source) is not None):
            return Decision(
                False,
                f"IP source {ip_source} non déclarée au mandat (Art.3 : {mandat.ip_source})",
                ref,
            )

    return Decision(True, f"autorisé : {type_test} sur {extraire_hote(cible)} ({raison})", ref)


# ----------------------------------------------------------------- utilitaires
_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def extraire_hote(cible: str) -> str:
    """Extrait l'hôte d'une URL/domaine/IP, sans résolution réseau.

    Accepte « https://x.cm/a », « x.cm:443 », « user@x.cm », « 1.2.3.0/24 ».
    Ne fait AUCUNE requête DNS ni réseau.
    """
    if cible is None:
        return ""
    s = str(cible).strip()
    if not s:
        return ""
    s = _SCHEME_RE.sub("", s)       # retire le schéma éventuel
    s = s.split("@", 1)[-1]         # retire user:pass@
    s = s.split("/", 1)[0]          # retire le chemin OU le masque CIDR
    s = s.split("#", 1)[0].split("?", 1)[0]
    # port (mais pas pour une IPv6 entre crochets [..]:port)
    if s.startswith("["):
        s = s[1:].split("]", 1)[0]
    elif s.count(":") == 1:
        s = s.split(":", 1)[0]
    return s.strip().rstrip(".").lower()


def _norm_domaine(d) -> str:
    return str(d).strip().rstrip(".").lower()


def _domaine_correspond(hote: str, motif: str) -> bool:
    """hote correspond-il au motif ? Un motif « exemple.cm » couvre ses sous-domaines.

    Un motif « *.exemple.cm » ne couvre QUE les sous-domaines (pas l'apex).
    La correspondance est faite par étiquettes (labels), jamais par sous-chaîne,
    pour éviter le piège « exemple.cm » ⊃ « exemple.cm.evil.net ».
    """
    hote = _norm_domaine(hote)
    motif = _norm_domaine(motif)
    if motif.startswith("*."):
        base = motif[2:]
        return hote != base and hote.endswith("." + base)
    return hote == motif or hote.endswith("." + motif)


def _comme_ip(valeur: str):
    try:
        return ipaddress.ip_address(str(valeur))
    except ValueError:
        return None


def _ip_dans(ip, plage: str) -> bool:
    if ip is None:
        return False
    try:
        reseau = ipaddress.ip_network(str(plage), strict=False)
    except ValueError:
        # plage peut être une IP simple
        hote = _comme_ip(plage)
        return hote is not None and hote == ip
    return ip in reseau


def _reseaux_valides(valeurs, souci, label: str) -> list[str]:
    """Filtre une liste d'IP/plages : garde les valides, signale les invalides via `souci`."""
    out: list[str] = []
    for v in (valeurs or []):
        s = str(v).strip()
        try:
            ipaddress.ip_network(s, strict=False)
            out.append(s)
        except ValueError as e:
            souci(f"{label} : IP/plage invalide : {s!r} ({e})")
    return out


def _as_date(v) -> _dt.date:
    if isinstance(v, _dt.datetime):
        return v.date()
    if isinstance(v, _dt.date):
        return v
    return _dt.date.fromisoformat(str(v))


def _as_time(v) -> _dt.time:
    if isinstance(v, _dt.time):
        return v
    s = str(v).strip()
    if s.count(":") == 1:   # "HH:MM" -> "HH:MM:00"
        s += ":00"
    return _dt.time.fromisoformat(s)


def _moment_aware(moment: _dt.datetime | None) -> _dt.datetime:
    if moment is None:
        return _dt.datetime.now(_dt.timezone.utc)
    if moment.tzinfo is None:
        return moment.replace(tzinfo=_dt.timezone.utc)
    return moment
