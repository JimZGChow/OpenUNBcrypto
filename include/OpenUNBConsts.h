#ifndef OPENUNBCONSTS_H
#define OPENUNBCONSTS_H

// Time defines
#define S2M(x)  (x/60)           // seconds to minutes
#define M2H(x)  (x/60)           // minutes to hours
#define H2M(x)  (x*60)           // hours to minutes
#define M2S(x)  (x*60)           // minutes to seconds
#define M(x)    (x*60)           // minutes to seconds
#define H(x)    (M(x)*60)        // hours to seconds
#define MS2M(x)		(S2M(MS2S(x)))		// ms to min
#define MS2H(x)		(M2H(S2M(MS2S(x))))	// ms to hours
#define MS2S(x)		(x/1000)    // ms to sec

#define H2S(x)		(x*60*60)	// hours to sec


#define  EPOCH_DURATION  H(4)

#endif // OPENUNBCONSTS_H
