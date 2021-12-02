# TP2 : Stéganographie, signature, etc ...

Nicolas Commandeur

Benjamin Verdant

## INFO 1002

[Sujet du TP](https://www.lama.univ-savoie.fr/pagesmembres/hyvernat/Enseignement/2122/info002/tp2.html)

Run before anythign else `pip install -r requirements.txt`


Toutes les questions jusqu'à la 5 ont été traités.

Les commandes pour les tests sont les suivantes :

```bash
    # Print the helper
    $ python main.py --help

    # Generate a pair of keys (a pair is already generated)
    # output : public.key and private.key
    $ python main.py --pair

    # Generate a certificate for a user
    # output :  certificate/Armstrong_Lance.png (cert) and sign/Armstrong_Lance.png.sig (signature)
    $ python main.py --generate "Armstrong" "Lance" "13"

    # Verify a certificate with the signature
    $ python main.py --validate "Armstrong_Lance.png" "Armstrong_Lance.png.sig"

    # Read in the file the size and the message in the next line
    $ python main.py --read "Armstrong_Lance.png" 0

    # Write the message size and the message in the file
    $ python main.py --hide-message "Armstrong_Lance.png" 0 "Hello World"

    # Validation error
    $ python main.py --validate "verdant_benjamin_falsified.png" "verdant_benjamin.png.sig"
```

La documentation est dans le dossier tp/info1002-TP2.
