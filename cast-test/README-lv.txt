MANA DZIESMU GRĀMATA — GOOGLE CAST MINIMĀLAIS TESTS

Faili:
- receiver.html — minimāls uztvērējs ar melnu fonu un baltiem dziesmas vārdiem.
- sender-test.html — testa sūtītājs, kurā ievada Application ID, nosaukumu un dziesmas tekstu.

Svarīgi:
1. Šis ir sākuma prototips, vēl nav pārbaudīts īstā Google TV ierīcē.
2. Custom Web Receiver testēšanai Google prasa Cast SDK Developer Console reģistrāciju un Application ID. Google norāda vienreizēju, neatmaksājamu 5 USD maksu.
3. Uztvērējam vajag publiski sasniedzamu HTTPS adresi. Statiskai lapai var izmantot bezmaksas mitināšanu, piemēram, GitHub Pages vai Firebase Hosting; iestatīšana prasa atsevišķas darbības.
4. Google Cast konsolē reģistrē receiver.html HTTPS URL kā Custom Receiver un reģistrē Google TV ierīci testēšanai. Android TV ierīcei var būt jāatrod Cast programmatūras sērijas numurs.
5. Atver sender-test.html izvietoto HTTPS adresi Google Chrome pārlūkā, ievadi Application ID, nospied “Savienot ar TV”, pēc tam “Rādīt dziesmu TV”.

Ja TV parādās melns fons ar baltiem vārdiem, minimālais uztvērējs darbojas. Tikai pēc veiksmīga testa integrēsim sūtītāja funkciju galvenajā dziesmu grāmatā. Galveno HTML failu līdz tam nemaini.
