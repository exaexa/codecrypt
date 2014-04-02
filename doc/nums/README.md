
# Nothing Up My Sleeve

For running of XSYND a great deal of random initialization material is needed;
it's exactly around 32kbits of bitstream for parity-check matrices that needs
to look uniformly random. Great candidate for hiding errors.

This directory contains C programs that were used to generate the initial
constants. Matrix A1 is filled with (binary) digits of `sqrt(2)-1`, A2 is made
the same way from `sqrt(3)-1`.

Compile with `-lgmp`.
