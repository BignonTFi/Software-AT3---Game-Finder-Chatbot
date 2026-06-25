import json
import os
import sys
from difflib import get_close_matches


# ── Colour helpers (gracefully degrade if terminal doesn't support ANSI) ──────

def supports_colour():
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

USE_COLOUR = supports_colour()

class C:
    RESET  = "\033[0m"  if USE_COLOUR else ""
    BOLD   = "\033[1m"  if USE_COLOUR else ""
    DIM    = "\033[2m"  if USE_COLOUR else ""
    CYAN   = "\033[96m" if USE_COLOUR else ""
    GREEN  = "\033[92m" if USE_COLOUR else ""
    YELLOW = "\033[93m" if USE_COLOUR else ""
    RED    = "\033[91m" if USE_COLOUR else ""
    PURPLE = "\033[95m" if USE_COLOUR else ""

def score_colour(score):
    if score >= 90: return C.GREEN
    if score >= 75: return C.YELLOW
    return C.RED

def header(text):
    width = 52
    print(f"\n{C.CYAN}{C.BOLD}{'─' * width}")
    print(f"  {text}")
    print(f"{'─' * width}{C.RESET}")

def estimate_knownness(game):
    score = 10
    score += min(len(game.get('platforms', [])), 6) * 8

    series = game.get('series', '').strip().lower()
    if series and series != 'standalone':
        score += 15

    try:
        release_year = int(game.get('release_date', '0')[:4])
    except (TypeError, ValueError):
        release_year = 0

    if release_year and release_year < 2000:
        score += 15
    elif release_year and release_year < 2010:
        score += 10
    elif release_year and release_year < 2018:
        score += 5

    meta = game.get('metacritic_score', 0)
    if meta >= 90:
        score += 10
    elif meta >= 85:
        score += 5

    popular_tags = {
        'multiplayer', 'co-op', 'open-world', 'battle royale', 'sports',
        'fighting', 'sandbox', 'racing', 'nintendo', 'mario', 'zelda',
        'minecraft', 'grand theft auto'
    }
    tags = ' '.join(game.get('tags', [])).lower()
    if any(tag in tags for tag in popular_tags):
        score += 10

    return max(0, min(100, score))

def game_line(game, show_desc=False):
    score = game.get('metacritic_score', 0)
    col   = score_colour(score)
    title = game['title']
    genre = game['genre']
    price = game.get('launch_price', 0)
    rating = game.get('rating', '?')
    knownness = game.get('knownness_score')
    if knownness is None:
        knownness = estimate_knownness(game)
    print(f"  {C.BOLD}{title}{C.RESET}")
    print(f"  {C.DIM}{genre}  ·  {col}{score}/100{C.RESET}  ·  {C.DIM}${price:.2f}  ·  {rating}{C.RESET}")
    print(f"  {C.DIM}Knownness score: {knownness}/100{C.RESET}")
    if show_desc and 'short_description' in game:
        print(f"  {C.DIM}{game['short_description']}{C.RESET}")
    print()


# ── Database loading ───────────────────────────────────────────────────────────

def load_database(filename='games_db.json'):
    if not os.path.exists(filename):
        print(f"{C.RED}Error: '{filename}' not found. Place it in the same directory.{C.RESET}")
        sys.exit(1)
    with open(filename, 'r') as f:
        db = json.load(f)
    return db


# ── Stats summary ─────────────────────────────────────────────────────────────

def show_stats(db):
    header("Database summary")
    genres  = {}
    platforms = {}
    scores  = [g['metacritic_score'] for g in db]

    for g in db:
        genres[g['genre']] = genres.get(g['genre'], 0) + 1
        for p in g.get('platforms', []):
            platforms[p] = platforms.get(p, 0) + 1

    print(f"  Total games    : {C.BOLD}{len(db)}{C.RESET}")
    print(f"  Avg score      : {C.BOLD}{sum(scores)/len(scores):.1f}{C.RESET}")
    print(f"  Highest score  : {C.GREEN}{C.BOLD}{max(scores)}{C.RESET}  ({next(g['title'] for g in db if g['metacritic_score'] == max(scores))})")
    print(f"  Lowest score   : {C.YELLOW}{min(scores)}{C.RESET}  ({next(g['title'] for g in db if g['metacritic_score'] == min(scores))})")
    avg_price = sum(g.get('launch_price', 0) for g in db) / len(db)
    print(f"  Avg launch price: ${avg_price:.2f}")

    print(f"\n  {C.BOLD}Top genres:{C.RESET}")
    for genre, count in sorted(genres.items(), key=lambda x: -x[1])[:6]:
        bar = '█' * count
        print(f"    {genre:<30} {C.CYAN}{bar}{C.RESET} {count}")

    print(f"\n  {C.BOLD}Top platforms:{C.RESET}")
    for platform, count in sorted(platforms.items(), key=lambda x: -x[1])[:8]:
        print(f"    {platform:<20} {count} games")


# ── Filter helpers ─────────────────────────────────────────────────────────────

def filter_by_score(db, min_score=90):
    header(f"Games with score ≥ {min_score}")
    results = sorted(
        [g for g in db if g['metacritic_score'] >= min_score],
        key=lambda g: -g['metacritic_score']
    )
    if not results:
        print(f"  {C.DIM}No games found.{C.RESET}\n")
        return
    for g in results:
        game_line(g)
    print(f"  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


def filter_by_genre(db, genre=None):
    if genre is None:
        genres = sorted(set(g['genre'] for g in db))
        print(f"\n  {C.BOLD}Available genres:{C.RESET}")
        for i, g in enumerate(genres, 1):
            print(f"    {i:>2}. {g}")
        choice = input("\n  Enter genre name (or part of it): ").strip()
        matches = [g for g in genres if choice.lower() in g.lower()]
        if not matches:
            close = get_close_matches(choice, genres, n=1, cutoff=0.5)
            if close:
                print(f"  Did you mean '{close[0]}'? Using that.")
                genre = close[0]
            else:
                print(f"  {C.RED}No matching genre.{C.RESET}")
                return
        elif len(matches) == 1:
            genre = matches[0]
        else:
            print(f"  Multiple matches: {', '.join(matches)}")
            genre = matches[0]
            print(f"  Using: {genre}")

    header(f"Genre: {genre}")
    results = sorted(
        [g for g in db if genre.lower() in g['genre'].lower()],
        key=lambda g: -g['metacritic_score']
    )
    for g in results:
        game_line(g, show_desc=True)
    print(f"  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


def filter_by_platform(db, platform=None):
    if platform is None:
        all_platforms = sorted(set(p for g in db for p in g.get('platforms', [])))
        print(f"\n  {C.BOLD}Available platforms:{C.RESET}")
        for p in all_platforms:
            print(f"    • {p}")
        platform = input("\n  Enter platform: ").strip()

    header(f"Games on: {platform}")
    results = sorted(
        [g for g in db if any(platform.lower() in p.lower() for p in g.get('platforms', []))],
        key=lambda g: -g['metacritic_score']
    )
    if not results:
        print(f"  {C.DIM}No games found for that platform.{C.RESET}\n")
        return
    for g in results:
        game_line(g)
    print(f"  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


def filter_by_tag(db):
    all_tags = sorted(set(t for g in db for t in g.get('tags', [])))
    print(f"\n  {C.BOLD}Available tags:{C.RESET}")
    cols = 3
    for i in range(0, len(all_tags), cols):
        row = all_tags[i:i+cols]
        print("    " + "  ".join(f"{t:<22}" for t in row))
    tag = input("\n  Enter tag: ").strip()

    header(f"Tag: {tag}")
    results = sorted(
        [g for g in db if any(tag.lower() in t.lower() for t in g.get('tags', []))],
        key=lambda g: -g['metacritic_score']
    )
    if not results:
        print(f"  {C.DIM}No games found with that tag.{C.RESET}\n")
        return
    for g in results:
        game_line(g, show_desc=True)
    print(f"  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


def filter_by_era(db):
    print(f"\n  {C.BOLD}Eras:{C.RESET}")
    print("    1. Classic   (before 2000)")
    print("    2. 2000s     (2000–2009)")
    print("    3. 2010s     (2010–2019)")
    print("    4. Modern    (2020–present)")
    choice = input("\n  Choose era [1-4]: ").strip()
    ranges = {
        '1': (0,    2000, "Classic (before 2000)"),
        '2': (2000, 2010, "2000s"),
        '3': (2010, 2020, "2010s"),
        '4': (2020, 9999, "Modern (2020–present)"),
    }
    if choice not in ranges:
        print(f"  {C.RED}Invalid choice.{C.RESET}")
        return
    lo, hi, label = ranges[choice]
    header(f"Era: {label}")
    results = sorted(
        [g for g in db if lo <= int(g['release_date'][:4]) < hi],
        key=lambda g: g['release_date']
    )
    for g in results:
        game_line(g)
    print(f"  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


def filter_by_budget(db):
    try:
        budget = float(input("\n  Max price ($): ").strip())
    except ValueError:
        print(f"  {C.RED}Invalid number.{C.RESET}")
        return
    header(f"Games under ${budget:.2f}")
    results = sorted(
        [g for g in db if g.get('launch_price', 9999) <= budget],
        key=lambda g: g.get('launch_price', 0)
    )
    for g in results:
        price = g.get('launch_price', 0)
        print(f"  {C.BOLD}{g['title']}{C.RESET}  {C.GREEN}${price:.2f}{C.RESET}  ·  {C.DIM}{g['genre']}{C.RESET}")
    print(f"\n  {C.DIM}Found {len(results)} game(s).{C.RESET}\n")


# ── Recommendation engine ──────────────────────────────────────────────────────

def recommend(db):
    header("Game recommender")

    print(f"\n  {C.BOLD}What genres interest you?{C.RESET}")
    genres = sorted(set(g['genre'] for g in db))
    for i, g in enumerate(genres, 1):
        print(f"    {i:>2}. {g}")
    raw = input("\n  Enter genre numbers (comma-separated, or Enter to skip): ").strip()
    chosen_genres = []
    if raw:
        for part in raw.split(','):
            try:
                chosen_genres.append(genres[int(part.strip()) - 1])
            except (ValueError, IndexError):
                pass

    print(f"\n  {C.BOLD}What platform are you on?{C.RESET}")
    all_platforms = sorted(set(p for g in db for p in g.get('platforms', [])))
    for i, p in enumerate(all_platforms, 1):
        print(f"    {i:>2}. {p}")
    raw_p = input("\n  Platform number (or Enter to skip): ").strip()
    chosen_platform = None
    if raw_p:
        try:
            chosen_platform = all_platforms[int(raw_p) - 1]
        except (ValueError, IndexError):
            pass

    try:
        min_score = int(input("\n  Minimum Metacritic score [default 80]: ").strip() or "80")
    except ValueError:
        min_score = 80

    try:
        max_price = float(input("  Max price (or Enter for any): ").strip() or "9999")
    except ValueError:
        max_price = 9999

    # Score each game
    scored = []
    for g in db:
        points = 0
        if g['metacritic_score'] < min_score:
            continue
        if g.get('launch_price', 9999) > max_price:
            continue
        if chosen_platform and not any(chosen_platform.lower() in p.lower() for p in g.get('platforms', [])):
            continue
        if chosen_genres:
            for cg in chosen_genres:
                if cg.lower() in g['genre'].lower():
                    points += 3
        points += (g['metacritic_score'] - 80) / 4
        scored.append((g, points))

    scored.sort(key=lambda x: -x[1])
    header("Recommendations for you")
    if not scored:
        print(f"  {C.YELLOW}No matches found. Try relaxing your filters.{C.RESET}\n")
        return
    for g, _ in scored[:5]:
        game_line(g, show_desc=True)


# ── Search by title ───────────────────────────────────────────────────────────

def search_title(db):
    query = input("\n  Search title: ").strip().lower()
    if not query:
        return
    results = [g for g in db if query in g['title'].lower()]
    if not results:
        titles = [g['title'] for g in db]
        close = get_close_matches(query, [t.lower() for t in titles], n=3, cutoff=0.4)
        if close:
            print(f"\n  {C.DIM}No exact match. Did you mean:{C.RESET}")
            for c in close:
                match = next(g for g in db if g['title'].lower() == c)
                game_line(match, show_desc=True)
        else:
            print(f"  {C.RED}No results for '{query}'.{C.RESET}\n")
        return
    header(f"Search results: '{query}'")
    for g in results:
        game_line(g, show_desc=True)


# ── Main menu ──────────────────────────────────────────────────────────────────

MENU = [
    ("Database summary",           lambda db: show_stats(db)),
    ("Filter by Metacritic score", lambda db: filter_by_score(db, int(input("\n  Min score [default 90]: ").strip() or "90"))),
    ("Filter by genre",            lambda db: filter_by_genre(db)),
    ("Filter by platform",         lambda db: filter_by_platform(db)),
    ("Filter by tag",              lambda db: filter_by_tag(db)),
    ("Filter by era",              lambda db: filter_by_era(db)),
    ("Filter by budget",           lambda db: filter_by_budget(db)),
    ("Get recommendations",        lambda db: recommend(db)),
    ("Search by title",            lambda db: search_title(db)),
]

def main():
    db = load_database()
    print(f"\n{C.CYAN}{C.BOLD}  Video Game Database  {C.RESET}{C.DIM}({len(db)} games){C.RESET}")

    while True:
        print(f"\n{C.BOLD}  Main menu{C.RESET}")
        for i, (label, _) in enumerate(MENU, 1):
            print(f"    {C.DIM}{i}.{C.RESET} {label}")
        print(f"    {C.DIM}0.{C.RESET} Quit")

        choice = input(f"\n  {C.BOLD}>{C.RESET} ").strip()
        if choice == '0':
            print(f"\n  {C.DIM}Bye!{C.RESET}\n")
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(MENU):
                MENU[idx][1](db)
            else:
                print(f"  {C.RED}Invalid choice.{C.RESET}")
        except (ValueError, KeyboardInterrupt):
            print(f"\n  {C.DIM}Cancelled.{C.RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.DIM}Interrupted.{C.RESET}\n")