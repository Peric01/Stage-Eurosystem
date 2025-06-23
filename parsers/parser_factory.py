from .cowrie_parser import CowrieParser

'''
Factory per la creazione di parser in base al tipo richiesto.

La factory consente di istanziare il parser corretto in modo dinamico
senza dover scrivere il codice di una classe specifica nel codice di alto livello.

'''

def get_parser(name: str):
    if name.lower() == "cowrie":
        return CowrieParser()
    raise ValueError(f"No parser found for {name}")