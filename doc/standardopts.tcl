proc ConfigureOption {option arglist desc} {
    set result "
    <DT><B><CODE><I>cipherProc</I> configure $option $arglist</CODE></B></DT>
	<DD>$desc
	</DD>
	<P>
"

    return $result
}

proc CgetOption {option desc} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget $option</CODE></B></DT>
	<DD>$desc
	</DD>
	<P>
"

    return $result
}

proc ConfigureCt {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> configure -ciphertext string</CODE></B></DT>
    <DT><B><CODE><I>cipherProc</I> configure -ct string</CODE></B></DT>
	<DD>Set the ciphertext for this cipher instance to <B>string</B>.
	Invalid letters or numbers in the ciphertext are silently discarded.
	</DD>
	<P>
"

    return $result
}

proc ConfigurePeriod {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> configure -period n</CODE></B></DT>
	<DD>Set the period for this cipher to <B>n</B>.
	<P>
"

    return $result
}

proc ConfigureStepinterval {{isValid 1}} {
    if {$isValid} {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -stepinterval n</CODE></B></DT>
	<DD>Set the display interval while solving to <B>n</B>.  The
	<I><B>stepcommand</B></I> procedure will be called for every
	<B>n</B>th iteration while solving.  This is used to provide user
	feedback while solving is taking place.
	</DD>
	<P>
"
    } else {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -stepinterval n</CODE></B></DT>
	<DD>This option has no effect for this cipher type.
	</DD>
	<P>
"
    }

    return $result
}

proc ConfigureStepcommand {{isValid 1}} {
    if {$isValid} {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -stepcommand <I>proc</I></CODE></B></DT>
	<DD>Set the display command while solving to <B><I>proc</I></B>.  This
	command will be called for every <B>n</B>th iteration while solving.
	The arguments for this procedure are:
	<P>
	<B><CODE><I>stepcommand</I> iter key pt</CODE></B>
	<P>
	<B>iter</B> is the current iteration number.  <B>key</B> is the
	current value of the key that is being used.  <B>pt</B> is the
	plaintext that is produced with this key.
	</DD>
	<P>
"
    } else {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -stepcommand <I>proc</I></CODE></B></DT>
	<DD>This option has no effect for this cipher type.
	</DD>
	<P>
"
    }

    return $result
}

proc ConfigureBestfitcommand {{isValid 1}} {
    if {$isValid} {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -bestfitcommand <I>proc</I></CODE></B></DT>
	<DD>Set the best fit display command while solving to
	<B><I>proc</I></B>.  This command will be called every time a better
	solution is found while autosolving.
	The arguments for this procedure are:
	<P>
	<B><CODE><I>bestfitcommand</I> iter key value pt</CODE></B>
	<P>
	<B>iter</B> is the current iteration number.  <B>key</B> is the
	current value of the key that is being used.  <B>value</B> is the
	value of the metric used to judge how good this solution is.  The
	<B>value</B> is often a digram or trigram frequency count.  <B>pt</B>
	is the plaintext that is produced with this key.
	</DD>
	<P>
"
    } else {
	set result "
    <DT><B><CODE><I>cipherProc</I> configure -bestfitcommand <I>proc</I></CODE></B></DT>
	<DD>This option has no effect for this cipher type.
	</DD>
	<P>
"
    }

    return $result
}

proc ConfigureLanguage {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> configure -language <I>language</I></CODE></B></DT>
	<DD><B>This option is currently ignored for all cipher types.</B>  Set
	the current cipher language to <B><I>language</I></B>.  If the cipher
	has a solve method then digram frequencies for this language are used
	to determine the best fit.  If the language is not specified or not
	known then english is used.
"

    return $result
}

proc CgetType {} {
    global cipherType

    set result "
    <DT><B><CODE><I>cipherProc</I> cget -type</CODE></B></DT>
	<DD>Returns the type of this cipher.  In this case, <B>$cipherType</B>
	</DD>
	<P>
"

    return $result
}

proc CgetCt {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -ciphertext</CODE></B></DT>
    <DT><B><CODE><I>cipherProc</I> cget -ct</CODE></B></DT>
	<DD>Return the ciphertext for this cipher.
	</DD>
	<P>
"

    return $result
}

proc CgetPt {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -plaintext</CODE></B></DT>
    <DT><B><CODE><I>cipherProc</I> cget -pt</CODE></B></DT>
	<DD>Return the plaintext for this cipher based on the current
	key setting.
	</DD>
	<P>
"

    return $result
}

proc CgetKey {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -key</CODE></B></DT>
	<DD>Returns the current key setting for this cipher.  The result
	can be passed back to this cipher instance or another cipher
	with the <I>cipherProc restore</I> subcommand.
	</DD>
	<P>
"

    return $result
}

proc CgetLength {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -length</CODE></B></DT>
	<DD>Returns the length of the ciphertext for this cipher.  <B>0</B>
	is returned if the ciphertext has not been set.
	</DD>
	<P>
"

    return $result
}

proc CgetPeriod {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -period</CODE></B></DT>
	<DD>Return the period for this cipher.
	</DD>
	<P>
"

    return $result
}

proc CgetStepinterval {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -stepinterval</CODE></B></DT>
	<DD>Returns the current value of the stepinterval.
	</DD>
	<P>
"

    return $result
}

proc CgetStepcommand {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -stepcommand</CODE></B></DT>
	<DD>Returns the name of the procedure currently set for the
	<B>stepcommand</B>.  An empty string is returned if no stepcommand
	is set.
	</DD>
	<P>
"

    return $result
}

proc CgetBestfitcommand {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -bestfitcommand</CODE></B></DT>
	<DD>Returns the name of the procedure currently set for the
	<B>bestfitcommand</B>.  An empty string is returned if no bestfitcommand
	is set.
	</DD>
	<P>
"

    return $result
}

proc CgetLanguage {} {
    set result "
    <DT><B><CODE><I>cipherProc</I> cget -language</CODE></B></DT>
	<DD>Returns the name of the language used for this cipher.
	</DD>
	<P>
"

    return $result
}
