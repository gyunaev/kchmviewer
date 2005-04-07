/* $Id$ */
/***************************************************************************
 *          enum_chmLib.c - CHM archive test driver                        *
 *                           -------------------                           *
 *                                                                         *
 *  author:     Jed Wing <jedwin@ugcs.caltech.edu>                         *
 *  notes:      This is a quick-and-dirty test driver for the chm lib      *
 *              routines.  The program takes as its input the paths to one *
 *              or more .chm files.  It attempts to open each .chm file in *
 *              turn, and display a listing of all of the files in the     *
 *              archive.                                                   *
 *                                                                         *
 *              It is not included as a particularly useful program, but   *
 *              rather as a sort of "simplest possible" example of how to  *
 *              use the enumerate portion of the API.                      *
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU Lesser General Public License as        *
 *   published by the Free Software Foundation; either version 2.1 of the  *
 *   License, or (at your option) any later version.                       *
 *                                                                         *
 ***************************************************************************/

#include "chm_lib.h"
#include <stdio.h>
#include <stdlib.h>

/*
 * callback function for enumerate API
 */
int _print_ui(struct chmFile *h,
              struct chmUnitInfo *ui,
              void *context)
{
    printf("   %1d %8d %8d   %s\n",
           (int)ui->space,
           (int)ui->start,
           (int)ui->length,
           ui->path);
    return CHM_ENUMERATOR_CONTINUE;
}

int main(int c, char **v)
{
    struct chmFile *h;
    int i;

    for (i=1; i<c; i++)
    {
        h = chm_open(v[i]);
        if (h == NULL)
        {
            fprintf(stderr, "failed to open %s\n", v[i]);
            exit(1);
        }

        printf("%s:\n", v[i]);
        printf(" spc    start   length   name\n");
        printf(" ===    =====   ======   ====\n");

        if (! chm_enumerate(h,
                            CHM_ENUMERATE_ALL,
                            _print_ui,
                            NULL))
            printf("   *** ERROR ***\n");

        chm_close(h);
    }

    return 0;
}
