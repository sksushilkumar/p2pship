
all:
	gcc -shared `pkg-config gtk+-2.0 libosso hildon-1 libhildondesktop hildon-desktop --libs --cflags` p2pship_sb.c p2pship_sb_dialog.c p2pship_sb_text_dialog.c -o libp2pship.so

dist-ip70: all
	scp libp2pship.so root@ip70.infrahip.net:/usr/lib/hildon-desktop/

dist-ip105: all
	scp libp2pship.so root@ip105.infrahip.net:/usr/lib/hildon-desktop/

dist-44: all
	scp libp2pship.so root@10.0.0.44:/usr/lib/hildon-desktop/

install: all
	cp libp2pship.so /usr/lib/hildon-desktop/
	mkdir /usr/share/p2pship_statusbar/
	cp -r ../data/icons ../data/sb /usr/share/p2pship_statusbar/
	cp ../data/p2pship_sb.desktop /usr/share/applications/hildon-status-bar/
