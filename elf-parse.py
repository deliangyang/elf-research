

with open('data/hello', 'rb') as f:
    print(f.read(64))

    print('-' * 64)

    print(f.read(56))

    print('-' * 64)

    shdr = f.read(64)
    # get sh_name
    sh_name = shdr[:4]
    print(sh_name)
