module SessionsHelper

  # Logs in the given user
  def sign_in(user)
    # cookies.permanent[:remember_token] = user.remember_token
    # self.current_user = user
    session[:user_id] = user.id
  end

  # Returns the current signed-in user (if any)
  def current_user
    if (user_id = session[:user_id])
      @current_user ||= User.find_by(id: user_id)
    elsif (user_id = cookies.signed[:user_id])
      user = User.find_by(id: user_id)
      if user && user.authenticated?(:remember, cookies[:remember_token])
        sign_in user
        @current_user = user
      end
    end
  end

  # Returns T if user is logged in, F otherwise
  def signed_in?
    !current_user.nil?
  end

  # Remembers a user in a persistent session
  def remember(user)
    user.remember
    cookies.permanent.signed[:user_id] = user.id
    cookies.permanent[:remember_token] = user.remember_token
  end

  # Returns true if the given user is the current user
  def current_user?(user)
    user == current_user
    # @current_user ||= User.find_by_remember_token(cookies[:remember_token])
    # @current_user ||= User.find_by(id: session[:user_id])
  end

  def correct_user
    @user = User.find(params[:id])
    redirect_to(root_url) unless user == current_user
  end

  # Redirects to stored location ( or to the default)
  def redirect_back_or(default)
    redirect_to(session[:forwarding_url] || default)
    session.delete(:forwarding_url)
  end

  # Stores the URL trying to be accessed
  def store_location
    session[:forwarding_url] = request.url if request.get?
  end

  # Forgets a persistent session
  def forget(user)
    user.forget
    cookies.delete(:user_id)
    cookies.delete(:remember_token)
  end

  def log_out
    forget(current_user)
    session.delete(:user_id)
    @current_user = nil
  end

end
