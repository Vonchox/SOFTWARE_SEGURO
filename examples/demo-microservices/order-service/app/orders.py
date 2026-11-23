def inspect_page(request, repository):
    page_size = request.params["count"]
    return repository.fetch_page(page_size)
