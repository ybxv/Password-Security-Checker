"""Password Security Checker & Brute-force crack time estimator."""

import argparse
from dataclasses import dataclass
from decimal import Decimal
import getpass
import math
import re
import sys
from typing import List, Tuple
import unittest

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CHARSET_LOWER = 26
CHARSET_UPPER = 26
CHARSET_DIGITS = 10
CHARSET_SYMBOLS = 33

COMMON_PASSWORDS: set[str] = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "welcome", "ninja",
    "admin", "master", "sunshine", "princess", "football", "iloveyou",
    "monkey", "senha", "senha123", "mudar123", "brasil", "102030",
    "flamengo", "corinthians", "chocolate", "superman", "batman",
    "secret", "login", "teste", "guest", "default", "root",
    "pass123", "charlie", "starwars", "pokemon", "computer",
    "shadow", "ashley", "michael", "jessica", "daniel", "jordan",
    "hannah", "alexander", "letmein", "trustno1"
}

ATTACK_SCENARIOS = [
    ("Ataque online com limitação (rate-limiting)", 100, "100 tent/s"),
    ("Ataque offline com hardware comum (CPU)", 1_000_000_000, "1 bilhão tent/s"),
    ("Ataque offline com cluster de GPUs", 100_000_000_000, "100 bilhões tent/s"),
]

KEYBOARD_ROWS = [
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "1234567890",
]


@dataclass
class CriterionResult:
    id: int
    name: str
    passed: bool
    details: str = ""


@dataclass
class ScenarioEstimate:
    name: str
    speed_display: str
    avg_time: str
    worst_time: str


@dataclass
class SecurityReport:
    password_length: int
    criteria: List[CriterionResult]
    charset_size: int
    entropy_bits: float
    search_space: int
    estimates: List[ScenarioEstimate]
    classification: str
    penalized: bool
    penalty_reasons: List[str]
    suggestions: List[str]


def check_length(password: str) -> CriterionResult:
    n = len(password)
    if n >= 16:
        return CriterionResult(1, "Comprimento mínimo de 8 caracteres", True, f"Excelente ({n} caracteres: 16+)")
    if n >= 12:
        return CriterionResult(1, "Comprimento mínimo de 8 caracteres", True, f"Muito bom ({n} caracteres: 12+)")
    if n >= 8:
        return CriterionResult(1, "Comprimento mínimo de 8 caracteres", True, f"Adequado ({n} caracteres)")
    return CriterionResult(1, "Comprimento mínimo de 8 caracteres", False, f"Muito curta ({n} caracteres, mínimo recomendado é 8)")


def check_lowercase(password: str) -> CriterionResult:
    ok = any(c.islower() for c in password)
    return CriterionResult(2, "Contém letras minúsculas (a-z)", ok, "Presente" if ok else "Ausente")


def check_uppercase(password: str) -> CriterionResult:
    ok = any(c.isupper() for c in password)
    return CriterionResult(3, "Contém letras maiúsculas (A-Z)", ok, "Presente" if ok else "Ausente")


def check_digits(password: str) -> CriterionResult:
    ok = any(c.isdigit() for c in password)
    return CriterionResult(4, "Contém números (0-9)", ok, "Presente" if ok else "Ausente")


def check_symbols(password: str) -> CriterionResult:
    ok = any(not c.isalnum() for c in password)
    return CriterionResult(5, "Contém símbolos/caracteres especiais", ok, "Presente" if ok else "Ausente")


def check_not_only_digits(password: str) -> CriterionResult:
    if not password:
        return CriterionResult(6, "Não é composta apenas por números", False, "Vazia")
    ok = not password.isdigit()
    return CriterionResult(6, "Não é composta apenas por números", ok, "Variada" if ok else "Composta apenas por dígitos")


def check_not_only_letters(password: str) -> CriterionResult:
    if not password:
        return CriterionResult(7, "Não é composta apenas por letras", False, "Vazia")
    ok = not password.isalpha()
    return CriterionResult(7, "Não é composta apenas por letras", ok, "Variada" if ok else "Composta apenas por letras")


def detect_obvious_sequences(password: str) -> Tuple[bool, List[str]]:
    if len(password) < 3:
        return False, []

    detected: List[str] = []
    pwd_lower = password.lower()

    repeat_match = re.search(r"(.)\1{2,}", password)
    if repeat_match:
        detected.append(f"Repetição consecutiva ('{repeat_match.group(0)}')")

    for i in range(len(pwd_lower) - 2):
        chunk = pwd_lower[i:i + 3]
        ords = [ord(c) for c in chunk]
        if chunk.isalpha():
            if ords[1] - ords[0] == 1 and ords[2] - ords[1] == 1:
                detected.append(f"Sequência alfabética ('{chunk}')")
            elif ords[0] - ords[1] == 1 and ords[1] - ords[2] == 1:
                detected.append(f"Sequência alfabética decrescente ('{chunk}')")
        elif chunk.isdigit():
            if ords[1] - ords[0] == 1 and ords[2] - ords[1] == 1:
                detected.append(f"Sequência numérica ('{chunk}')")
            elif ords[0] - ords[1] == 1 and ords[1] - ords[2] == 1:
                detected.append(f"Sequência numérica decrescente ('{chunk}')")

    for row in KEYBOARD_ROWS:
        rev_row = row[::-1]
        for i in range(len(pwd_lower) - 2):
            sub = pwd_lower[i:i + 3]
            if sub in row:
                detected.append(f"Sequência de teclado QWERTY ('{sub}')")
            elif sub in rev_row:
                detected.append(f"Sequência de teclado invertida ('{sub}')")

    unique_detected = list(dict.fromkeys(detected))
    return len(unique_detected) > 0, unique_detected


def check_no_obvious_sequences(password: str) -> CriterionResult:
    has_seq, details = detect_obvious_sequences(password)
    if has_seq:
        return CriterionResult(8, "Não contém sequências óbvias", False, f"Detectado: {', '.join(details[:2])}")
    return CriterionResult(8, "Não contém sequências óbvias", True, "Nenhum padrão óbvio encontrado")


def check_not_common_password(password: str) -> CriterionResult:
    is_common = password.strip().lower() in COMMON_PASSWORDS
    if is_common:
        return CriterionResult(9, "Não está no top ~50 de senhas mais comuns", False, "Consta em lista de senhas públicas conhecidas!")
    return CriterionResult(9, "Não está no top ~50 de senhas mais comuns", True, "Não encontrada na lista das mais comuns")


def calculate_effective_charset(password: str) -> int:
    if not password:
        return 0

    charset = 0
    if any(c.islower() for c in password):
        charset += CHARSET_LOWER
    if any(c.isupper() for c in password):
        charset += CHARSET_UPPER
    if any(c.isdigit() for c in password):
        charset += CHARSET_DIGITS
    if any(not c.isalnum() for c in password):
        charset += CHARSET_SYMBOLS

    return charset


def calculate_entropy(password: str, charset: int) -> float:
    length = len(password)
    if length == 0 or charset <= 0:
        return 0.0
    return length * math.log2(charset)


def calculate_search_space(password: str, charset: int) -> int:
    length = len(password)
    if length == 0 or charset <= 0:
        return 0
    if length > 100:
        return -1
    return charset ** length


def format_search_space(length: int, charset: int, search_space: int) -> str:
    if length == 0 or charset <= 0:
        return "0 combinações"
    if length <= 6 and 0 <= search_space < 10**12:
        return f"{search_space:,} combinações".replace(",", ".")

    try:
        log10_total = length * math.log10(charset)
        exponent = int(log10_total)
        mantissa = 10 ** (log10_total - exponent)
        return f"~{mantissa:.3f}e+{exponent} combinações"
    except Exception:
        return "astronômico (> 10^1000 combinações)"


def format_duration(seconds: Decimal) -> str:
    if seconds <= Decimal("0"):
        return "0 segundos"
    if seconds < Decimal("0.001"):
        return "quase instantâneo (< 1 milissegundo)"
    if seconds < Decimal("1"):
        ms = seconds * Decimal("1000")
        return f"{ms:.2f} milissegundos".replace(".", ",")
    if seconds < Decimal("60"):
        return f"{seconds:.2f} segundos".replace(".", ",")

    minutes = seconds / Decimal("60")
    if minutes < Decimal("60"):
        return f"{minutes:.1f} minutos".replace(".", ",")

    hours = minutes / Decimal("60")
    if hours < Decimal("24"):
        return f"{hours:.1f} horas".replace(".", ",")

    days = hours / Decimal("24")
    if days < Decimal("365.25"):
        return f"{days:.1f} dias".replace(".", ",")

    years = days / Decimal("365.25")
    if years < Decimal("100"):
        return f"{years:.1f} anos".replace(".", ",")

    centuries = years / Decimal("100")
    if centuries < Decimal("10"):
        return f"{centuries:.1f} séculos ({int(years):,} anos)".replace(",", ".")

    millennia = years / Decimal("1000")
    if millennia < Decimal("1000"):
        return f"{millennia:.1f} milênios ({int(years):,} anos)".replace(",", ".")

    millions = years / Decimal("1000000")
    if millions < Decimal("1000"):
        return f"mais de {millions:.1f} milhões de anos".replace(".", ",")

    billions = years / Decimal("1000000000")
    if billions < Decimal("1000"):
        return f"mais de {billions:.1f} bilhões de anos".replace(".", ",")

    trillions = years / Decimal("1000000000000")
    if trillions < Decimal("1000000"):
        return f"mais de {trillions:.1f} trilhões de anos".replace(".", ",")

    try:
        log10_years = int(years.log10())
        return f"mais de 10^{log10_years} anos (praticamente inquebrável)"
    except Exception:
        return "mais de 10^100 anos (inquebrável)"


def estimate_crack_times(length: int, charset: int, search_space: int) -> List[ScenarioEstimate]:
    estimates: List[ScenarioEstimate] = []

    if length == 0 or charset <= 0:
        for name, _, speed_disp in ATTACK_SCENARIOS:
            estimates.append(ScenarioEstimate(name, speed_disp, "0 segundos", "0 segundos"))
        return estimates

    # Para senhas muito longas, calcula via log10 para evitar estouro de memória
    if length > 80:
        log10_space = length * math.log10(charset)
        log10_year_seconds = math.log10(31557600)

        for name, speed, speed_disp in ATTACK_SCENARIOS:
            log10_speed = math.log10(speed)
            log10_worst_sec = log10_space - log10_speed
            log10_avg_sec = log10_worst_sec - math.log10(2)

            log10_worst_years = log10_worst_sec - log10_year_seconds
            log10_avg_years = log10_avg_sec - log10_year_seconds

            estimates.append(
                ScenarioEstimate(
                    name=name,
                    speed_display=speed_disp,
                    avg_time=f"mais de 10^{int(log10_avg_years)} anos (praticamente inquebrável)",
                    worst_time=f"mais de 10^{int(log10_worst_years)} anos (praticamente inquebrável)"
                )
            )
        return estimates

    space_dec = Decimal(search_space)
    for name, speed, speed_disp in ATTACK_SCENARIOS:
        speed_dec = Decimal(speed)
        worst_sec = space_dec / speed_dec if speed_dec > 0 else Decimal("0")
        avg_sec = (space_dec / Decimal("2")) / speed_dec if speed_dec > 0 else Decimal("0")

        estimates.append(
            ScenarioEstimate(
                name=name,
                speed_display=speed_disp,
                avg_time=format_duration(avg_sec),
                worst_time=format_duration(worst_sec)
            )
        )

    return estimates


def classify_security(
    entropy: float,
    length: int,
    is_common: bool,
    has_sequences: bool,
    only_numbers_or_letters: bool
) -> Tuple[str, bool, List[str]]:
    penalties: List[str] = []

    if entropy < 28.0:
        base_class = "Muito fraca"
    elif entropy < 45.0:
        base_class = "Fraca"
    elif entropy < 60.0:
        base_class = "Razoável"
    elif entropy < 80.0:
        base_class = "Forte"
    else:
        base_class = "Muito forte"

    final_class = base_class

    if is_common:
        penalties.append("Senha consta no ranking das 50 mais comuns do mundo (quebrada instantaneamente por ataque de dicionário).")
        final_class = "Muito fraca"

    if has_sequences:
        penalties.append("Contém sequências óbvias ou repetições facilmente exploradas por regras de mutação (ex.: Hashcat/John the Ripper).")
        hierarchy = ["Muito fraca", "Fraca", "Razoável", "Forte", "Muito forte"]
        current_idx = hierarchy.index(final_class)
        penalty_step = 2 if length < 10 else 1
        new_idx = max(0, current_idx - penalty_step)
        final_class = hierarchy[new_idx]

    if length < 8 and final_class in ("Razoável", "Forte", "Muito forte"):
        penalties.append("Comprimento inferior a 8 caracteres inviabiliza segurança robusta.")
        final_class = "Fraca"

    return final_class, len(penalties) > 0, penalties


def generate_suggestions(
    password: str,
    criteria: List[CriterionResult],
    is_common: bool,
    has_sequences: bool
) -> List[str]:
    suggestions: List[str] = []
    length = len(password)

    if is_common:
        suggestions.append("Troque esta senha com urgência! Ela faz parte de dicionários públicos usados por cibercriminosos.")

    if length < 8:
        suggestions.append("Aumente o comprimento para no mínimo 8 caracteres (recomendado: 12 a 16+ caracteres).")
    elif length < 12:
        suggestions.append("Considere expandir para 12 a 16 caracteres para elevar a resistência a ataques offline.")

    passed_map = {c.id: c.passed for c in criteria}

    if not passed_map.get(2, True):
        suggestions.append("Adicione letras minúsculas (a-z) para diversificar o conjunto de caracteres.")
    if not passed_map.get(3, True):
        suggestions.append("Adicione letras maiúsculas (A-Z) para elevar o espaço de busca.")
    if not passed_map.get(4, True):
        suggestions.append("Adicione números (0-9) distribuídos pelo corpo da senha.")
    if not passed_map.get(5, True):
        suggestions.append("Inclua símbolos especiais (@, #, $, %, !, &, *, etc.) para maximizar o charset.")

    if not passed_map.get(6, True):
        suggestions.append("Evite senhas puramente numéricas: elas possuem um charset minúsculo (apenas 10 possibilidades por dígito).")
    if not passed_map.get(7, True):
        suggestions.append("Evite senhas compostas apenas por letras; misture dígitos e pontuação.")

    if has_sequences:
        suggestions.append("Remova sequências alfabéticas ('abc'), numéricas ('123') ou de teclado ('qwerty') e caracteres repetidos ('aaaa').")

    if not suggestions or len(suggestions) <= 1:
        suggestions.append("Considere utilizar uma frase-senha (Passphrase) com 4+ palavras não relacionadas (ex.: 'cavalo-bateria-grampo-alegre') gerada via Diceware.")

    return suggestions


def analyze_password(password: str) -> SecurityReport:
    length = len(password)

    criteria = [
        check_length(password),
        check_lowercase(password),
        check_uppercase(password),
        check_digits(password),
        check_symbols(password),
        check_not_only_digits(password),
        check_not_only_letters(password),
        check_no_obvious_sequences(password),
        check_not_common_password(password),
    ]

    charset_size = calculate_effective_charset(password)
    entropy_bits = calculate_entropy(password, charset_size)
    search_space = calculate_search_space(password, charset_size)
    estimates = estimate_crack_times(length, charset_size, search_space)

    is_common = not criteria[8].passed
    has_sequences = not criteria[7].passed
    only_numbers_or_letters = not criteria[5].passed or not criteria[6].passed

    classification, penalized, penalties = classify_security(
        entropy_bits, length, is_common, has_sequences, only_numbers_or_letters
    )

    suggestions = generate_suggestions(password, criteria, is_common, has_sequences)

    return SecurityReport(
        password_length=length,
        criteria=criteria,
        charset_size=charset_size,
        entropy_bits=entropy_bits,
        search_space=search_space,
        estimates=estimates,
        classification=classification,
        penalized=penalized,
        penalty_reasons=penalties,
        suggestions=suggestions
    )


def print_report(report: SecurityReport) -> None:
    sep = "=" * 78
    sub_sep = "-" * 78

    print("\n" + sep)
    print("        RELATÓRIO DE ANÁLISE DE SEGURANÇA E RESISTÊNCIA DE SENHA")
    print(sep)

    print("\n[+] CHECKLIST DOS CRITÉRIOS DE SEGURANÇA:")
    print(sub_sep)
    for c in report.criteria:
        icon = "✅" if c.passed else "❌"
        status_txt = "APROVADO" if c.passed else "REPROVADO"
        detail_txt = f" - {c.details}" if c.details else ""
        print(f" {icon} [{status_txt:9s}] {c.id}. {c.name}{detail_txt}")

    print("\n[+] MÉTRICAS DO ESPAÇO DE BUSCA E ENTROPIA:")
    print(sub_sep)
    print(f" • Comprimento da senha:  {report.password_length} caracteres")
    print(f" • Tamanho do Charset:    {report.charset_size} caracteres disponíveis")
    print(f" • Entropia calculada:    {report.entropy_bits:.2f} bits de Shannon")
    
    search_space_disp = format_search_space(report.password_length, report.charset_size, report.search_space)
    print(f" • Espaço de busca (C^L): {search_space_disp}")

    print("\n[+] TEMPO ESTIMADO DE QUEBRA POR FORÇA BRUTA PURA:")
    print(sub_sep)
    print(f" {'CENÁRIO DE ATAQUE':<44} | {'TEMPO MÉDIO (50%)':<14} | {'PIOR CASO (100%)'}")
    print(sub_sep)
    for est in report.estimates:
        scenario_label = f"{est.name} ({est.speed_display})"
        if len(scenario_label) > 43:
            scenario_label = scenario_label[:40] + "..."
        print(f" {scenario_label:<44} | {est.avg_time:<17} | {est.worst_time}")

    if report.penalized:
        print("\n" + "!" * 78)
        print(" [!] ALERTA DE VULNERABILIDADE / PENALIDADE APLICADA:")
        for r in report.penalty_reasons:
            print(f"   ⚠️  {r}")
        print("   Nota: O tempo de força bruta acima é HIPER-OTIMISTA! Um atacante que")
        print("   utilize dicionários ou regras de mutação quebrará a senha quase INSTANTANEAMENTE.")
        print("!" * 78)

    badge_colors = {
        "Muito fraca": "🔴 MUITO FRACA",
        "Fraca": "🟠 FRACA",
        "Razoável": "🟡 RAZOÁVEL",
        "Forte": "🟢 FORTE",
        "Muito forte": "💎 MUITO FORTE",
    }
    badge = badge_colors.get(report.classification, report.classification.upper())

    print("\n[+] CLASSIFICAÇÃO FINAL DA SENHA:")
    print(sub_sep)
    print(f" >>> Nível de Segurança: [ {badge} ] <<<")

    print("\n[+] SUGESTÕES ESPECÍFICAS PARA MELHORIA:")
    print(sub_sep)
    for idx, sug in enumerate(report.suggestions, 1):
        print(f"  {idx}. {sug}")

    print("\n[i] LIMITAÇÕES DO MODELO MATEMÁTICO (NOTA DE SEGURANÇA):")
    print(sub_sep)
    print(" • O cálculo assume força bruta exaustiva onde todas as combinações são testadas.")
    print(" • Não cobre: ataques de dicionário avançados, rainbow tables (para hashes sem salt),")
    print("   nem engenharia social, credential stuffing ou spyware.")
    print(" • As velocidades reais dependem drasticamente da função de derivação de chave:")
    print("   Hashes rápidos (MD5/SHA256) permitem bilhões de hashes/s, enquanto algoritmos")
    print("   modernos com fator de trabalho (Argon2id, bcrypt, PBKDF2) tornam a quebra offline")
    print("   milhões de vezes mais lenta e cara.")
    print(sep + "\n")


class TestPasswordSecurityChecker(unittest.TestCase):

    def test_charset_calculation(self):
        self.assertEqual(calculate_effective_charset("123456"), 10)
        self.assertEqual(calculate_effective_charset("abc"), 26)
        self.assertEqual(calculate_effective_charset("Abc"), 52)
        self.assertEqual(calculate_effective_charset("Abc123"), 62)
        self.assertEqual(calculate_effective_charset("Abc123!@#"), 95)
        self.assertEqual(calculate_effective_charset(""), 0)

    def test_entropy_calculation(self):
        self.assertEqual(calculate_entropy("", 0), 0.0)
        e_num = calculate_entropy("12345678", 10)
        self.assertAlmostEqual(e_num, 8 * math.log2(10), places=4)
        e_complex = calculate_entropy("a" * 16, 95)
        self.assertAlmostEqual(e_complex, 16 * math.log2(95), places=4)

    def test_search_space(self):
        self.assertEqual(calculate_search_space("123", 10), 1000)
        self.assertEqual(calculate_search_space("", 10), 0)
        self.assertEqual(calculate_search_space("a", 26), 26)

    def test_sequence_detection(self):
        has_seq, _ = detect_obvious_sequences("xabcz")
        self.assertTrue(has_seq)
        has_seq, _ = detect_obvious_sequences("senha12345")
        self.assertTrue(has_seq)
        has_seq, _ = detect_obvious_sequences("k_qwerty_9")
        self.assertTrue(has_seq)
        has_seq, _ = detect_obvious_sequences("mypasswordaaaa")
        self.assertTrue(has_seq)
        has_seq, _ = detect_obvious_sequences("k9#Vq!2mZp$Lx8wR")
        self.assertFalse(has_seq)

    def test_common_passwords(self):
        self.assertFalse(check_not_common_password("123456").passed)
        self.assertFalse(check_not_common_password("password").passed)
        self.assertTrue(check_not_common_password("k9#Vq!2mZp$Lx8wR").passed)

    def test_duration_formatting(self):
        self.assertIn("instantâneo", format_duration(Decimal("0.0005")))
        self.assertIn("segundos", format_duration(Decimal("15.5")))
        self.assertIn("minutos", format_duration(Decimal("120")))
        self.assertIn("horas", format_duration(Decimal("7200")))
        self.assertIn("dias", format_duration(Decimal(86400 * 2)))
        self.assertIn("anos", format_duration(Decimal(31557600 * 5)))
        self.assertIn("milhões de anos", format_duration(Decimal(31557600 * 2000000)))

    def test_penalties_application(self):
        rep = analyze_password("123456")
        self.assertEqual(rep.classification, "Muito fraca")
        self.assertTrue(rep.penalized)

        rep_strong = analyze_password("k9#Vq!2mZp$Lx8wR")
        self.assertEqual(rep_strong.classification, "Muito forte")
        self.assertFalse(rep_strong.penalized)


def run_demonstration() -> None:
    samples = [
        ("123456", "Caso 1: Senha extremamente comum e curta"),
        ("senhaforte", "Caso 2: Apenas letras minúsculas (palavra de dicionário)"),
        ("Abc12345", "Caso 3: Combina maiúscula, minúscula e números, mas possui sequências óbvias"),
        ("k9#Vq!2mZp$Lx8wR", "Caso 4: Alta entropia (16 caracteres, charset completo 95)"),
    ]

    print("\n" + "#" * 78)
    print(" DEMONSTRAÇÃO DO PASSWORD SECURITY CHECKER")
    print("#" * 78)

    for pwd, desc in samples:
        print(f"\n>>> TESTANDO SENHA: '{pwd}' - {desc}")
        report = analyze_password(pwd)
        print_report(report)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Password Security Checker & Estimador Criptográfico de Força Bruta."
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        help="Senha a ser analisada."
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Executa os testes unitários."
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Executa a demonstração com 4 senhas de teste."
    )

    args = parser.parse_args()

    if args.test:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestPasswordSecurityChecker)
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)

    if args.demo:
        run_demonstration()
        sys.exit(0)

    if args.password is not None:
        target_password = args.password
    else:
        print("=" * 78)
        print("  PASSWORD SECURITY CHECKER")
        print("  Por segurança, os caracteres digitados não serão exibidos.")
        print("  Digite a senha e pressione [ENTER].")
        print("=" * 78)

        target_password = ""
        while not target_password:
            try:
                target_password = getpass.getpass("Digite a senha: ")
            except (KeyboardInterrupt, EOFError):
                print("\nOperação cancelada.")
                sys.exit(0)

            if not target_password:
                print("  Nenhuma senha informada. Tente novamente.")

    report = analyze_password(target_password)
    print_report(report)

    if args.password is None:
        try:
            input("\nPressione [ENTER] para encerrar...")
        except (KeyboardInterrupt, EOFError):
            pass


if __name__ == "__main__":
    main()
