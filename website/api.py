from tmdbv3api import TMDb
from tmdbv3api import TV
tmdb = TMDb()
tmdb.api_key = 'c369400f245e2cf5ff6e7311bba5486f'
tmdb.language = 'en'
tmdb.debug = True

tv = TV()
show = tv.search('fate')


for res in show:
    vote = res.vote_average
    poster = res.poster_path
    movie_id = res.id
    name = res.name 
    overview = res.overview
    print(vote)
    print(poster)
    print(name)
    print(overview)
    print(movie_id)
    