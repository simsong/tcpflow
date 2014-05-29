if test x"${mingw}" != "xyes" ; then

  case $host in
    *mingw*)
       AC_MSG_NOTICE([Compiling under mingw; will not search other directories.])
       ;;
    *)
       AC_MSG_NOTICE(Compiling under $host.)
       # Bring additional directories where things might be found into our
       # search path. I don't know why autoconf doesn't do this by default
       for spfx in /usr/local /opt/local /sw /usr/local/ssl; do
         AC_MSG_NOTICE([checking ${spfx}/include])
         if test -d ${spfx}/include; then
           CPPFLAGS="-I${spfx}/include $CPPFLAGS"
           LDFLAGS="-L${spfx}/lib $LDFLAGS"
           AC_MSG_NOTICE([ *** ADDING ${spfx}/include to CPPFLAGS *** ])
           AC_MSG_NOTICE([ *** ADDING ${spfx}/lib to LDFLAGS *** ])
         fi
       done
       AC_MSG_NOTICE([ CPPFLAGS = ${CPPFLAGS} ])        
       AC_MSG_NOTICE([ LDFLAGS = ${LDFLAGS} ])        
       ;;
  esac
fi


