from core.detector import AntiPhishingDetector

def main():
    detector = AntiPhishingDetector()
    
    print("=" * 60)
    print("🛡️  SHIELDGUARD - DETECTOR DE PHISHING E GOLPES DE MERCADO")
    print("=" * 60)

    # Caso real do golpe do Mercado Pago
    mensagem_teste = (
        "Mercado Pago: Prezado cliente, identificamos um acesso suspeito. "
        "Valide suas credenciais para evitar o bloqueio da conta: "
        "http://securitypaymentsafe.digital/login"
    )

    print("\n📩 Mensagem Recebida para Análise:")
    print(f'"{mensagem_teste}"\n')

    resultado = detector.analisar_mensagem(mensagem_teste)

    print("-" * 60)
    print(f"DIAGNÓSTICO: {resultado['status']}")
    print(f"SCORE DE RISCO: {resultado['maior_score']}/100")
    print("-" * 60)
    
    for link_info in resultado["links_analisados"]:
        print(f"\n🔗 Link: {link_info['url_analisada']}")
        print("🔍 Evidências Encontradas:")
        for motivo in link_info["motivos"]:
            print(f"  • {motivo}")

if __name__ == "__main__":
    main()