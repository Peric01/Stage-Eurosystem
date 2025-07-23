def ask_log_level(cli_choice=None):
    level_map = {
        "1": ("DEBUG", 10),
        "2": ("INFO", 20),
        "3": ("WARNING", 30)
    }

    if cli_choice and cli_choice in level_map:
        level_name, level = level_map[cli_choice]
        print(f"Livello di log impostato su: {level_name}\n")
    elif cli_choice and cli_choice not in level_map:
        print("Scelta da CLI non valida. Verrà utilizzato il livello di log predefinito: DEBUG\n")
        level_name, level = "DEBUG", 10
    else:
        print("Scegli il livello minimo di log:")
        print("1 - DEBUG")
        print("2 - INFO")
        print("3 - WARNING")
        print("Premi INVIO per utilizzare il livello predefinito: DEBUG")
        choice = input("Inserisci la tua scelta [1-3]: ").strip()
        if choice == "":
            print("Nessuna scelta effettuata. Verrà utilizzato il livello di log predefinito: DEBUG\n")
            level_name, level = "DEBUG", 10
        elif choice in level_map:
            level_name, level = level_map[choice]
            print(f"Livello di log impostato su: {level_name}\n")
        else:
            print("Scelta non valida. Verrà utilizzato il livello di log predefinito: DEBUG\n")
            level_name, level = "DEBUG", 10

    return level_name
