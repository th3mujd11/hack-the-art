Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html
  get "home/index"
  # Defines the root path route ("/")
  root "home#index"

  # Feedback (intentionally vulnerable name rendering for CTF)
  get "/feedback", to: "feedbacks#new", as: :feedback
  post "/feedback", to: "feedbacks#create"

  namespace :admin do
    get "/feedbacks", to: "feedbacks#index", as: :feedbacks
  end
end
