TODO:
Kernfunktionalitäten, die du implementieren könntest (steigernd in der Komplexität):

1. Symmetrische Verschlüsselung:

Generiere einen symmetrischen Schlüssel (z.B. AES-256).
Verschlüssle eine Benutzereingabe mit diesem Schlüssel.
Entschlüssle die verschlüsselte Nachricht.
Gib die Schritte und Ergebnisse auf der Konsole aus.

2. Asymmetrische Verschlüsselung (RSA):

Generiere ein Schlüsselpaar (öffentlich/privat).
Verschlüssle eine kurze Nachricht mit dem öffentlichen Schlüssel.
Entschlüssle mit dem privaten Schlüssel.
Achtung: Asymmetrische Verschlüsselung ist primär für den sicheren Schlüsselaustausch gedacht oder für kleine Datenmengen. Für große Nachrichten kombiniert man sie oft mit symmetrischer Kryptographie (Hybrid-Verfahren).

3. Hashing (SHA-256/SHA-512):

Berechne den Hash einer Benutzereingabe.
Zeige, wie eine minimale Änderung am Input einen komplett anderen Hash erzeugt.

4. Digitale Signaturen:

Signiere eine Nachricht mit einem privaten Schlüssel.
Verifiziere die Signatur mit dem passenden öffentlichen Schlüssel.
Zeige, was passiert, wenn die Nachricht oder die Signatur manipuliert wird. entschlüsselt den symmetrischen Schlüssel mit seinem privaten Schlüssel und kann dann Alices Nachrichten lesen.