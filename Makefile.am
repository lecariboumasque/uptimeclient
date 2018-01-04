bin_PROGRAMS=TUPm
TUPm_SOURCES = \
	TUPm.c base64_4_tup.c base64_4_tup.h md5_4_tup.c md5_4_tup.h minGlue.h minIni.c minIni.h TUPConvergence.c TUPConvergence.h TUPMonitor.c TUPMonitor.h TUPSocketFactory.c TUPSocketFactory.h sha2_4_tup.c sha2_4_tup.h

install-data-local:
		$(mkinstalldirs) $(prefix)/skel
	       	$(mkinstalldirs) $(prefix)/logs
		$(mkinstalldirs) $(prefix)/pid
		$(mkinstalldirs) $(prefix)/replay
		$(mkinstalldirs) $(prefix)/etc
		$(mkinstalldirs) $(prefix)/mon
		cp $(srcdir)/../etc/TUPm.conf $(prefix)/etc	
		cp $(srcdir)/../skel/*.c $(prefix)/skel/
		cp $(srcdir)/../skel/*.sh $(prefix)/skel/
		cp $(srcdir)/../mon/*.example $(prefix)/mon/
		mv $(prefix)/TUPmSkel $(prefix)/skel/
