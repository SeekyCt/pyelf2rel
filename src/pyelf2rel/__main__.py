from argparse import ArgumentParser

from pyelf2rel.elf2rel import main as elf2rel_main
from pyelf2rel.makelst import main as makelst_main


def main():
    parser = ArgumentParser()
    parser.add_argument("command", choices=["makelst", "pyelf2rel", "elf2rel"])
    parser.add_argument("arguments", type=str, nargs="*")
    args = parser.parse_args()

    if args.command == "makelst":
        makelst_main(args.arguments)
    else:
        elf2rel_main(args.arguments, ttyd_tools=args.command == "elf2rel")


if __name__ == "__main__":
    main()
