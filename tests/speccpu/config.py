from pathlib import Path

from hase.path import APP_ROOT

SPEC_PATH = APP_ROOT.joinpath("..", "spec").resolve()

SUITE_PATH = str(SPEC_PATH.joinpath("benchspec", "CPU")) + "/"

RUN_PATH = '/run/run_base_test_mytest-m64.0000/'

USAGE = str(APP_ROOT.joinpath('rusage.csv'))

INT_SPEED = ['600', '602', '605', '620', '623', '625', '631', '641', '648', '657']
FLOAT_SPEED = ['603', '607', '619', '621', '627', '628', '638', '644', '649', '654']

SUITE = {'600': {'commands': ['../run_base_test_mytest-m64.0000/perlbench_s_base.mytest-m64 '
                              '-I. -I./lib makerand.pl > makerand.out 2>> makerand.err',
                              '../run_base_test_mytest-m64.0000/perlbench_s_base.mytest-m64 '
                              '-I. -I./lib test.pl > test.out 2>> test.err'],
                 'name': '600.perlbench_s'},
         '602': {'commands': [], 'name': '602.gcc_s'},
         '603': {'commands': ['../run_base_test_mytest-m64.0000/speed_bwaves_base.mytest-m64 '
                              'bwaves_1 < bwaves_1.in > bwaves_1.out 2>> bwaves_1.err',
                              '../run_base_test_mytest-m64.0000/speed_bwaves_base.mytest-m64 '
                              'bwaves_2 < bwaves_2.in > bwaves_2.out 2>> bwaves_2.err'],
                 'name': '603.bwaves_s'},
         '605':  {'commands': ['../run_base_test_mytest-m64.0000/mcf_s_base.mytest-m64 '
                              'inp.in  > inp.out 2>> inp.err'],
                 'name': '605.mcf_s'},
         '607': {'commands': ['../run_base_test_mytest-m64.0000/cactuBSSN_s_base.mytest-m64 '
                              'spec_test.par   > spec_test.out 2>> spec_test.err'],
                 'name': '607.cactuBSSN_s'},
         '619': {'commands': ['../run_base_test_mytest-m64.0000/lbm_s_base.mytest-m64 '
                              '20 reference.dat 0 1 200_200_260_ldc.of > lbm.out 2>> '
                              'lbm.err'],
                 'name': '619.lbm_s'},
         '620': {'commands': ['../run_base_test_mytest-m64.0000/omnetpp_s_base.mytest-m64 '
                              '-c General -r 0 > omnetpp.General-0.out 2>> '
                              'omnetpp.General-0.err'],
                 'name': '620.omnetpp_s'},
         '621': {'commands': ['../run_base_test_mytest-m64.0000/wrf_s_base.mytest-m64 '
                              '> rsl.out.0000 2>> wrf.err'],
                 'name': '621.wrf_s'},
         '623': {'commands': ['../run_base_test_mytest-m64.0000/xalancbmk_s_base.mytest-m64 '
                              '-v test.xml xalanc.xsl > test-test.out 2>> '
                              'test-test.err'],
                 'name': '623.xalancbmk_s'},
         '625': {'commands': ['../run_base_test_mytest-m64.0000/x264_s_base.mytest-m64 '
                              '--dumpyuv 50 --frames 156 -o BuckBunny_New.264 '
                              'BuckBunny.yuv 1280x720 > '
                              'run_000-156_x264_s_base.mytest-m64_x264.out 2>> '
                              'run_000-156_x264_s_base.mytest-m64_x264.err'],
                 'name': '625.x264_s'},
         '627': {'commands': ['../run_base_test_mytest-m64.0000/cam4_s_base.mytest-m64 '
                              '> cam4_s_base.mytest-m64.txt 2>> '
                              'cam4_s_base.mytest-m64.err'],
                 'name': '627.cam4_s'},
         '628': {'commands': ['../run_base_test_mytest-m64.0000/speed_pop2_base.mytest-m64 '
                              '> pop2_s.out 2>> pop2_s.err'],
                 'name': '628.pop2_s'},
         '631': {'commands': ['../run_base_test_mytest-m64.0000/deepsjeng_s_base.mytest-m64 '
                              'test.txt > test.out 2>> test.err'],
                 'name': '631.deepsjeng_s'},
         '638': {'commands': ['../run_base_test_mytest-m64.0000/imagick_s_base.mytest-m64 '
                              '-limit disk 0 test_input.tga -shear 25 -resize 640x480 '
                              '-negate -alpha Off test_output.tga > test_convert.out '
                              '2>> test_convert.err'],
                 'name': '638.imagick_s'},
         '641': {'commands': ['../run_b ase_test_mytest-m64.0000/leela_s_base.mytest-m64 '
                              'test.sgf > test.out 2>> test.err'],
                 'name': '641.leela_s'},
         '644': {'commands': ['../run_base_test_mytest-m64.0000/nab_s_base.mytest-m64 '
                              'hkrdenq 1930344093 1000 > hkrdenq.out 2>> hkrdenq.err'],
                 'name': '644.nab_s'},
         '648': {'commands': ['../run_base_test_mytest-m64.0000/exchange2_s_base.mytest-m64 '
                              '0 > exchange2.txt 2>> exchange2.err'],
                 'name': '648.exchange2_s'},
         '649': {'commands': ['../run_base_test_mytest-m64.0000/fotonik3d_s_base.mytest-m64 '
                              '> fotonik3d_s.log 2>> fotonik3d_s.err'],
                 'name': '649.fotonik3d_s'},
         '654': {'commands': ['../run_base_test_mytest-m64.0000/sroms_base.mytest-m64 '
                              '< ocean_benchmark0.in > ocean_benchmark0.log 2>> '
                              'ocean_benchmark0.err'],
                 'name': '654.roms_s'},
         '657': {'commands': ['../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1548636 1555348 0 > cpu2006docs.tar-4-0.out 2>> '
                              'cpu2006docs.tar-4-0.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1462248 -1 1 > cpu2006docs.tar-4-1.out 2>> '
                              'cpu2006docs.tar-4-1.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1428548 -1 2 > cpu2006docs.tar-4-2.out 2>> '
                              'cpu2006docs.tar-4-2.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1034828 -1 3e > cpu2006docs.tar-4-3e.out 2>> '
                              'cpu2006docs.tar-4-3e.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1061968 -1 4 > cpu2006docs.tar-4-4.out 2>> '
                              'cpu2006docs.tar-4-4.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 4 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '1034588 -1 4e > cpu2006docs.tar-4-4e.out 2>> '
                              'cpu2006docs.tar-4-4e.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '650156 -1 0 > cpu2006docs.tar-1-0.out 2>> '
                              'cpu2006docs.tar-1-0.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '639996 -1 1 > cpu2006docs.tar-1-1.out 2>> '
                              'cpu2006docs.tar-1-1.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '637616 -1 2 > cpu2006docs.tar-1-2.out 2>> '
                              'cpu2006docs.tar-1-2.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '628996 -1 3e > cpu2006docs.tar-1-3e.out 2>> '
                              'cpu2006docs.tar-1-3e.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '631912 -1 4 > cpu2006docs.tar-1-4.out 2>> '
                              'cpu2006docs.tar-1-4.err',
                              '../run_base_test_mytest-m64.0000/xz_s_base.mytest-m64 '
                              'cpu2006docs.tar.xz 1 '
                              '055ce243071129412e9dd0b3b69a21654033a9b723d874b2015c774fac1553d9713be561ca86f74e4f16f22e664fc17a79f30caa5ad2c04fbc447549c2810fae '
                              '629064 -1 4e > cpu2006docs.tar-1-4e.out 2>> '
                              'cpu2006docs.tar-1-4e.err'],
                 'name': '657.xz_s'}}
