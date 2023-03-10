

Le compte-rendu ci-dessous reprend la méthode d'analyse forensique utilisée afin de récupérer le flag:

Contexte:
Un agent a trouvé une clé USB près du parking du commissariat. Il l'a donc apportée au service forensic pour savoir si cette clé était malveillante ou non avant de la brancher.

Introduction:

Dans un 1er temps, il va être nécessaire d'analyser le hash du fichier afin de déterminer si il est légitime ou non.

Analyse:

J'ai utilisé la commande suivante:sha256sum USB_Image

Voici ce que cela m'a retourné:
Hash SHA-256 du fichier :
a6fd7b3072187b2b6a31119f4580e58d5219fef157514c28d2de6df5ecf3185c USB_Image

J'ai essayé d'en savoir plus sur le format du fichier étant donné que sa taille était suspecte via la commande file:

file USB_Image : USB_Image: DOS/MBR boot sector, code offset 0x58+2, OEM-ID "MSDOS5.0", sectors/cluster 8, reserved sectors 1418, Media descriptor 0xf8, sectors/track 63, heads 255, hidden sectors 2048, sectors 7677952 (volumes > 32 MB), FAT (32 bit), sectors/FAT 7483, reserved 0x1, serial number 0xa84d68d6, unlabeled

En utilisant l'argument "strings" sur le fichier USB_Image, ainsi qu'faisant défiler les résultats dans un fichier : j'ai aperçu la ligne : "path=secret.png"
..
JVJV ECRET PNG JVJV [Trash Info] Path=secret.png DeletionDate=2023-02-10T22:21:51 IHDR sRGB gAMA

J'ai utilisé une commande pour tester le disque et donc tenter de récupérer des fichiers puis quelques images ont pu être récupérées. commande : photorec USB.Image
Un outil appelé "photorec" permet de récupérer des fichiers supprimés et de les intégrer dans un répertoire afin de les consulter.

Conclusion:

Parmi ces images,fichiers (6 au total : 2 jpg, 3 png et 1 fichier ini ) : des photos d'animaux et 2 contenant le contenu suivant : BOSCH {1MAG3}

Le fichier ini contenait lui : [Trash Info] Path=secret.png DeletionDate=2023-02-10T22:21:51

Cela m'a donc permis de trouver le flag avec l'utilisation de la commande strings.

Suite à l'analyse de la clé USB, elle ne présente aucun risque SSI. Elle peut donc être branché sans problème sur un ordinateur dédié à cet effet.
