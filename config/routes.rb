Rails.application.routes.draw do
  root 'movies#index'
  
  devise_for :users, controllers: { omniauth_callbacks: 'users/omniauth_callbacks' }
end
